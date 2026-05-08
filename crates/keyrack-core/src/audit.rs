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

//! Audit event schema, emitter trait, and built-in sinks.
//!
//! Every key operation emits an [`AuditEvent`] through an
//! [`AuditSink`]. The event is versioned (`schema_version`) so
//! consumers can handle schema evolution.
//!
//! Built-in sinks:
//!
//! - [`StdoutSink`] — JSON to stdout (dev/test).
//! - [`FileSink`] — append-only JSON-lines file (compliance fallback).
//! - NATS sink — lives in `keyrack-nats` crate; uses the subject
//!   convention from `KEYRACK_SPEC.md` §10 (`kms.audit.<event_id>`).
//!
//! The NATS sink is out-of-crate because `keyrack-core` must not
//! depend on a NATS client. The trait allows any sink implementation.

use crate::lid::Lid;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;

/// Actions that produce audit events. Vocabulary matches
/// `KEYRACK_SPEC.md` §3.1 / §11.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditAction {
    // Crypto ops
    #[serde(rename = "kms:Encrypt")]
    Encrypt,
    #[serde(rename = "kms:Decrypt")]
    Decrypt,
    #[serde(rename = "kms:GenerateDataKey")]
    GenerateDataKey,
    #[serde(rename = "kms:GenerateDataKeyWithoutPlaintext")]
    GenerateDataKeyWithoutPlaintext,
    #[serde(rename = "kms:ReEncrypt")]
    ReEncrypt,
    #[serde(rename = "kms:Sign")]
    Sign,
    #[serde(rename = "kms:Verify")]
    Verify,
    #[serde(rename = "kms:GenerateRandom")]
    GenerateRandom,

    // Key lifecycle
    #[serde(rename = "kms:CreateKey")]
    CreateKey,
    #[serde(rename = "kms:EnableKey")]
    EnableKey,
    #[serde(rename = "kms:DisableKey")]
    DisableKey,
    #[serde(rename = "kms:ScheduleKeyDeletion")]
    ScheduleKeyDeletion,
    #[serde(rename = "kms:CancelKeyDeletion")]
    CancelKeyDeletion,
    #[serde(rename = "kms:RotateKey")]
    RotateKey,

    // Key metadata / queries
    #[serde(rename = "kms:GetKey")]
    GetKey,
    #[serde(rename = "kms:DescribeKey")]
    DescribeKey,
    #[serde(rename = "kms:UpdateKey")]
    UpdateKey,
    #[serde(rename = "kms:ListKeys")]
    ListKeys,

    // Key versions
    #[serde(rename = "kms:ListKeyVersions")]
    ListKeyVersions,
    #[serde(rename = "kms:GetKeyVersion")]
    GetKeyVersion,

    // Rotation control
    #[serde(rename = "kms:EnableKeyRotation")]
    EnableKeyRotation,
    #[serde(rename = "kms:DisableKeyRotation")]
    DisableKeyRotation,
    #[serde(rename = "kms:GetKeyRotationStatus")]
    GetKeyRotationStatus,
    #[serde(rename = "kms:GetKeyRotationHistory")]
    GetKeyRotationHistory,
    #[serde(rename = "kms:GetKeyRotationPolicy")]
    GetKeyRotationPolicy,
    #[serde(rename = "kms:SetKeyRotationPolicy")]
    SetKeyRotationPolicy,

    // Hierarchy queries
    #[serde(rename = "kms:GetKeyDependents")]
    GetKeyDependents,
    #[serde(rename = "kms:GetKeyAncestors")]
    GetKeyAncestors,

    // Tags
    #[serde(rename = "kms:TagResource")]
    TagResource,
    #[serde(rename = "kms:UntagResource")]
    UntagResource,
    #[serde(rename = "kms:ListResourceTags")]
    ListResourceTags,

    // Aliases
    #[serde(rename = "kms:CreateAlias")]
    CreateAlias,
    #[serde(rename = "kms:DeleteAlias")]
    DeleteAlias,
    #[serde(rename = "kms:ListAliases")]
    ListAliases,

    // HSM connections
    #[serde(rename = "kms:CreateHsmConnection")]
    CreateHsmConnection,
    #[serde(rename = "kms:GetHsmConnection")]
    GetHsmConnection,
    #[serde(rename = "kms:ListHsmConnections")]
    ListHsmConnections,
    #[serde(rename = "kms:DeleteHsmConnection")]
    DeleteHsmConnection,
    #[serde(rename = "kms:GetHsmConnectionStatus")]
    GetHsmConnectionStatus,

    // Namespaces
    #[serde(rename = "kms:RegisterNamespace")]
    RegisterNamespace,
    #[serde(rename = "kms:ListNamespaces")]
    ListNamespaces,
    #[serde(rename = "kms:DescribeNamespace")]
    DescribeNamespace,

    // Rotation jobs
    #[serde(rename = "kms:ListRotationJobs")]
    ListRotationJobs,
    #[serde(rename = "kms:AcknowledgeRotationJob")]
    AcknowledgeRotationJob,
    #[serde(rename = "kms:CompleteRotationJob")]
    CompleteRotationJob,
    #[serde(rename = "kms:FailRotationJob")]
    FailRotationJob,

    // Cascade
    #[serde(rename = "kms:CascadeDisable")]
    CascadeDisable,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).unwrap_or_default();
        f.write_str(s.trim_matches('"'))
    }
}

/// High-level event categories.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    KeyCreated,
    KeyStateChanged,
    KeyRotated,
    KeyDeleted,
    KeyRead,
    CryptoOperation,
    TagMutation,
    AliasMutation,
    HsmConnectionMutation,
    RotationPolicyChanged,
    RotationJobStateChanged,
    NamespaceOperation,
    CascadeDisable,
    AuthorizationDenied,
}

/// Outcome of the audited operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Denied,
    Error,
}

/// Principal that initiated the operation. Opaque to `KeyRack`;
/// populated from the authentication layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPrincipal {
    pub id: String,
    #[serde(rename = "type")]
    pub principal_type: String,
}

/// Resource targeted by the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResource {
    pub id: String,
    #[serde(rename = "type")]
    pub resource_type: String,
}

impl AuditResource {
    /// Shorthand for a key resource.
    #[must_use]
    pub fn key(lid: &Lid) -> Self {
        Self {
            id: lid.to_string(),
            resource_type: "Key".into(),
        }
    }
}

/// Versioned audit event. Matches `SPEC.md` §5 envelope.
///
/// Fields `tenant`, `project`, and `srn` are included per
/// `KEYRACK_SPEC.md` §10 (populated by the service layer from the
/// authenticated request context — `keyrack-core` sets them to `None`
/// when not available).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub action: AuditAction,
    pub principal: AuditPrincipal,
    pub resource: AuditResource,
    pub result: AuditResult,

    /// BLAKE3 hash of the encryption context, hex-encoded. `None` for
    /// operations that don't involve encryption context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_context_hash: Option<String>,

    /// Tenant identifier (populated by service layer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,

    /// Project identifier (populated by service layer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    /// a partner Resource Name of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srn: Option<String>,

    /// Free-form metadata for action-specific details (e.g. state
    /// transition from/to, cascade duration, error message).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl AuditEvent {
    /// Create a new event with required fields; optional fields default
    /// to `None`/empty.
    #[must_use]
    pub fn new(
        event_type: EventType,
        action: AuditAction,
        principal: AuditPrincipal,
        resource: AuditResource,
        result: AuditResult,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            action,
            principal,
            resource,
            result,
            encryption_context_hash: None,
            tenant: None,
            project: None,
            srn: None,
            metadata: serde_json::Map::new(),
        }
    }

    /// Attach an encryption context hash.
    #[must_use]
    pub fn with_encryption_context_hash(mut self, hash: [u8; 32]) -> Self {
        use std::fmt::Write;
        let mut hex = String::with_capacity(64);
        for byte in hash {
            let _ = write!(hex, "{byte:02x}");
        }
        self.encryption_context_hash = Some(hex);
        self
    }

    /// Attach tenant/project/SRN context.
    #[must_use]
    pub fn with_context(
        mut self,
        tenant: Option<String>,
        project: Option<String>,
        srn: Option<String>,
    ) -> Self {
        self.tenant = tenant;
        self.project = project;
        self.srn = srn;
        self
    }

    /// Add a key-value pair to metadata.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Serialize to JSON bytes (for sinks).
    ///
    /// # Errors
    /// Returns an error if serialization fails (should not happen with
    /// well-formed events).
    pub fn to_json_bytes(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

// ────────────────────────────────────────────────────────────────────
// Sink trait
// ────────────────────────────────────────────────────────────────────

/// Async sink for audit events.
///
/// Sinks must be `Send + Sync` (shared across Tokio tasks).
/// The `emit` method should be non-blocking in the common case;
/// back-pressure handling is sink-specific.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Emit a single audit event.
    async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()>;

    /// Flush any buffered events. Called during graceful shutdown.
    async fn flush(&self) -> crate::error::Result<()> {
        Ok(())
    }
}

/// Fan-out sink that dispatches to multiple inner sinks.
pub struct FanoutSink {
    sinks: Vec<Box<dyn AuditSink>>,
}

impl FanoutSink {
    #[must_use]
    pub fn new(sinks: Vec<Box<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl AuditSink for FanoutSink {
    async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()> {
        for sink in &self.sinks {
            sink.emit(event).await?;
        }
        Ok(())
    }

    async fn flush(&self) -> crate::error::Result<()> {
        for sink in &self.sinks {
            sink.flush().await?;
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────
// Built-in sinks
// ────────────────────────────────────────────────────────────────────

/// JSON-to-stdout sink (dev/test).
pub struct StdoutSink;

#[async_trait]
impl AuditSink for StdoutSink {
    async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()> {
        let json = serde_json::to_string(event)
            .map_err(|e| crate::error::KeyRackError::Other(e.to_string()))?;
        println!("{json}");
        Ok(())
    }
}

/// Append-only JSON-lines file sink (compliance fallback).
pub struct FileSink {
    path: std::path::PathBuf,
}

impl FileSink {
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl AuditSink for FileSink {
    async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()> {
        use std::io::Write;
        let json = serde_json::to_vec(event)
            .map_err(|e| crate::error::KeyRackError::Other(e.to_string()))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| crate::error::KeyRackError::Other(e.to_string()))?;
        file.write_all(&json)
            .map_err(|e| crate::error::KeyRackError::Other(e.to_string()))?;
        file.write_all(b"\n")
            .map_err(|e| crate::error::KeyRackError::Other(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct CollectorSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl CollectorSink {
        fn new() -> (Self, Arc<Mutex<Vec<AuditEvent>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    events: Arc::clone(&events),
                },
                events,
            )
        }
    }

    #[async_trait]
    impl AuditSink for CollectorSink {
        async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[test]
    fn event_serialization_round_trip() {
        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "user:alice".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "lid_abc123".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.action, AuditAction::Encrypt);
        assert_eq!(parsed.result, AuditResult::Success);
        assert_eq!(parsed.principal.id, "user:alice");
    }

    #[test]
    fn action_display_format() {
        assert_eq!(AuditAction::Encrypt.to_string(), "kms:Encrypt");
        assert_eq!(AuditAction::CreateKey.to_string(), "kms:CreateKey");
        assert_eq!(AuditAction::CascadeDisable.to_string(), "kms:CascadeDisable");
    }

    #[test]
    fn event_with_encryption_context() {
        let hash = [0xABu8; 32];
        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "svc:volume".into(),
                principal_type: "Service".into(),
            },
            AuditResource {
                id: "lid_def456".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        )
        .with_encryption_context_hash(hash);

        let expected_hex = "ab".repeat(32);
        assert_eq!(event.encryption_context_hash.as_deref(), Some(expected_hex.as_str()));
    }

    #[test]
    fn event_with_context_fields() {
        let event = AuditEvent::new(
            EventType::KeyCreated,
            AuditAction::CreateKey,
            AuditPrincipal {
                id: "admin:seed".into(),
                principal_type: "Admin".into(),
            },
            AuditResource {
                id: "lid_001".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        )
        .with_context(
            Some("tenant-globex".into()),
            Some("proj-alpha".into()),
            Some("srn:kms:key:lid_001".into()),
        );

        assert_eq!(event.tenant.as_deref(), Some("tenant-globex"));
        assert_eq!(event.project.as_deref(), Some("proj-alpha"));
        assert_eq!(event.srn.as_deref(), Some("srn:kms:key:lid_001"));
    }

    #[test]
    fn metadata_roundtrip() {
        let mut event = AuditEvent::new(
            EventType::KeyStateChanged,
            AuditAction::DisableKey,
            AuditPrincipal {
                id: "admin:ops".into(),
                principal_type: "Admin".into(),
            },
            AuditResource {
                id: "lid_002".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );
        event.add_metadata("from_state", "enabled");
        event.add_metadata("to_state", "disabled");

        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.metadata.get("from_state").unwrap(), "enabled");
        assert_eq!(parsed.metadata.get("to_state").unwrap(), "disabled");
    }

    #[test]
    fn optional_fields_omitted_in_json() {
        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::GenerateRandom,
            AuditPrincipal {
                id: "svc:test".into(),
                principal_type: "Service".into(),
            },
            AuditResource {
                id: "system".into(),
                resource_type: "System".into(),
            },
            AuditResult::Success,
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("encryption_context_hash"));
        assert!(!json.contains("tenant"));
        assert!(!json.contains("project"));
        assert!(!json.contains("srn"));
        assert!(!json.contains("metadata"));
    }

    #[tokio::test]
    async fn collector_sink_captures_events() {
        let (sink, events) = CollectorSink::new();

        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Decrypt,
            AuditPrincipal {
                id: "svc:cinder".into(),
                principal_type: "Service".into(),
            },
            AuditResource {
                id: "lid_003".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        sink.emit(&event).await.unwrap();
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fanout_dispatches_to_all_sinks() {
        let (s1, e1) = CollectorSink::new();
        let (s2, e2) = CollectorSink::new();

        let fanout = FanoutSink::new(vec![Box::new(s1), Box::new(s2)]);

        let event = AuditEvent::new(
            EventType::KeyCreated,
            AuditAction::CreateKey,
            AuditPrincipal {
                id: "admin:bootstrap".into(),
                principal_type: "Admin".into(),
            },
            AuditResource {
                id: "lid_root".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        fanout.emit(&event).await.unwrap();

        assert_eq!(e1.lock().unwrap().len(), 1);
        assert_eq!(e2.lock().unwrap().len(), 1);
    }

    #[test]
    fn denied_event() {
        let event = AuditEvent::new(
            EventType::AuthorizationDenied,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "user:mallory".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "lid_secret".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Denied,
        );

        assert_eq!(event.result, AuditResult::Denied);
        assert_eq!(event.event_type, EventType::AuthorizationDenied);
    }

    #[test]
    fn all_actions_serialize_with_kms_prefix() {
        let actions = vec![
            AuditAction::Encrypt,
            AuditAction::Decrypt,
            AuditAction::GenerateDataKey,
            AuditAction::GenerateDataKeyWithoutPlaintext,
            AuditAction::ReEncrypt,
            AuditAction::Sign,
            AuditAction::Verify,
            AuditAction::GenerateRandom,
            AuditAction::CreateKey,
            AuditAction::EnableKey,
            AuditAction::DisableKey,
            AuditAction::ScheduleKeyDeletion,
            AuditAction::CancelKeyDeletion,
            AuditAction::RotateKey,
            AuditAction::GetKey,
            AuditAction::DescribeKey,
            AuditAction::UpdateKey,
            AuditAction::ListKeys,
            AuditAction::ListKeyVersions,
            AuditAction::GetKeyVersion,
            AuditAction::EnableKeyRotation,
            AuditAction::DisableKeyRotation,
            AuditAction::GetKeyRotationStatus,
            AuditAction::GetKeyRotationHistory,
            AuditAction::GetKeyRotationPolicy,
            AuditAction::SetKeyRotationPolicy,
            AuditAction::GetKeyDependents,
            AuditAction::GetKeyAncestors,
            AuditAction::TagResource,
            AuditAction::UntagResource,
            AuditAction::ListResourceTags,
            AuditAction::CreateAlias,
            AuditAction::DeleteAlias,
            AuditAction::ListAliases,
            AuditAction::CreateHsmConnection,
            AuditAction::GetHsmConnection,
            AuditAction::ListHsmConnections,
            AuditAction::DeleteHsmConnection,
            AuditAction::GetHsmConnectionStatus,
            AuditAction::RegisterNamespace,
            AuditAction::ListNamespaces,
            AuditAction::DescribeNamespace,
            AuditAction::ListRotationJobs,
            AuditAction::AcknowledgeRotationJob,
            AuditAction::CompleteRotationJob,
            AuditAction::FailRotationJob,
            AuditAction::CascadeDisable,
        ];

        for action in &actions {
            let s = action.to_string();
            assert!(s.starts_with("kms:"), "action {s} missing kms: prefix");
            let json = serde_json::to_string(action).unwrap();
            let roundtripped: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, roundtripped);
        }
    }
}
