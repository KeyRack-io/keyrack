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
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
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
    #[serde(rename = "kms:GenerateMac")]
    GenerateMac,
    #[serde(rename = "kms:VerifyMac")]
    VerifyMac,
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
    #[serde(rename = "kms:ReportKeyCompromise")]
    ReportKeyCompromise,
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

    // System background operations
    #[serde(rename = "kms:CascadeDisable")]
    CascadeDisable,
    #[serde(rename = "kms:RotationJobExpired")]
    RotationJobExpired,
    #[serde(rename = "kms:KeyDestroyed")]
    KeyDestroyed,

    // Secret-reference custody (HSM PIN custody / Scope B). Emitted when a
    // provider secret reference (e.g. a PKCS#11 `pin_ref`) is resolved.
    #[serde(rename = "kms:AccessSecret")]
    AccessSecret,

    // Scope ownership check on a backend connection (ADR-0001 A1.4).
    #[serde(rename = "kms:ScopeOwnerCheck")]
    ScopeOwnerCheck,
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
    KeyCompromised,
    CascadeDisable,
    AuthorizationDenied,
    SecretAccess,
    ScopeOwnerCheck,
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

    /// Stable resource name (SRN) of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srn: Option<String>,

    /// The x-request-id propagated from the incoming request. Enables
    /// end-to-end correlation across service boundaries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Free-form metadata for action-specific details (e.g. state
    /// transition from/to, cascade duration, error message).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,

    /// Ed25519 signature over the canonical JSON of this event (excluding signature fields).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Hex-encoded hash of the previous event's signature, forming a hash chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
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
            request_id: None,
            metadata: serde_json::Map::new(),
            signature: None,
            previous_hash: None,
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

    /// Attach the x-request-id for end-to-end correlation.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
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

// ────────────────────────────────────────────────────────────────────
// Audit event signer (tamper-evidence via Ed25519 + hash chain)
// ────────────────────────────────────────────────────────────────────

/// Signs audit events with Ed25519 and maintains a BLAKE3 hash chain
/// linking consecutive events for tamper evidence.
pub struct AuditSigner {
    signing_key: ed25519_dalek::SigningKey,
    previous_hash: Mutex<String>,
}

impl AuditSigner {
    /// Create a signer from an existing Ed25519 signing key.
    /// The hash chain starts with a zero hash (64 hex zeros).
    #[must_use]
    pub fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            signing_key,
            previous_hash: Mutex::new("0".repeat(64)),
        }
    }

    /// Generate a new random signing key.
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        Self::new(signing_key)
    }

    /// Sign an event in-place: sets `previous_hash` from the chain state,
    /// computes the Ed25519 signature over the canonical JSON (with signature
    /// fields excluded), then updates the chain hash.
    pub fn sign_event(&self, event: &mut AuditEvent) {
        let mut prev_hash = self.previous_hash.lock().unwrap();
        event.previous_hash = Some(prev_hash.clone());
        event.signature = None;

        let canonical =
            serde_json::to_string(event).expect("AuditEvent serialization should not fail");

        let sig = self.signing_key.sign(canonical.as_bytes());
        let sig_hex = hex_encode(sig.to_bytes().as_slice());

        event.signature = Some(sig_hex.clone());

        let new_hash = blake3::hash(sig_hex.as_bytes());
        *prev_hash = hex_encode(new_hash.as_bytes());
    }

    /// Returns the public verifying key for external consumers to verify events.
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Verify a signed audit event against a known verifying key.
    /// Returns `false` if the event is unsigned or the signature is invalid.
    #[must_use]
    pub fn verify_event(event: &AuditEvent, verifying_key: &ed25519_dalek::VerifyingKey) -> bool {
        let sig_hex = match &event.signature {
            Some(s) => s.clone(),
            None => return false,
        };

        let Some(sig_bytes) = hex_decode(&sig_hex) else {
            return false;
        };

        let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
            return false;
        };

        let mut verify_event = event.clone();
        verify_event.signature = None;

        let Ok(canonical) = serde_json::to_string(&verify_event) else {
            return false;
        };

        verifying_key.verify(canonical.as_bytes(), &sig).is_ok()
    }
}

// ────────────────────────────────────────────────────────────────────
// Signing audit sink (decorator)
// ────────────────────────────────────────────────────────────────────

/// A decorator sink that signs every event before forwarding to the inner sink.
pub struct SigningAuditSink {
    inner: Box<dyn AuditSink>,
    signer: AuditSigner,
}

impl SigningAuditSink {
    #[must_use]
    pub fn new(inner: Box<dyn AuditSink>, signer: AuditSigner) -> Self {
        Self { inner, signer }
    }

    /// Returns the verifying (public) key for this sink's signer.
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifying_key()
    }
}

#[async_trait]
impl AuditSink for SigningAuditSink {
    async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()> {
        let mut signed_event = event.clone();
        self.signer.sign_event(&mut signed_event);
        self.inner.emit(&signed_event).await
    }

    async fn flush(&self) -> crate::error::Result<()> {
        self.inner.flush().await
    }
}

// ────────────────────────────────────────────────────────────────────
// Hex helpers (avoids pulling in `hex` crate)
// ────────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
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
        assert_eq!(
            AuditAction::CascadeDisable.to_string(),
            "kms:CascadeDisable"
        );
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
        assert_eq!(
            event.encryption_context_hash.as_deref(),
            Some(expected_hex.as_str())
        );
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
        assert!(!json.contains("signature"));
        assert!(!json.contains("previous_hash"));
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
            AuditAction::AccessSecret,
        ];

        for action in &actions {
            let s = action.to_string();
            assert!(s.starts_with("kms:"), "action {s} missing kms: prefix");
            let json = serde_json::to_string(action).unwrap();
            let roundtripped: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, roundtripped);
        }
    }

    #[test]
    fn signer_signs_and_verifies() {
        let signer = AuditSigner::generate();
        let vk = signer.verifying_key();

        let mut event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "user:test".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "lid_sign_test".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        signer.sign_event(&mut event);

        assert!(event.signature.is_some());
        assert!(event.previous_hash.is_some());
        assert!(AuditSigner::verify_event(&event, &vk));
    }

    #[test]
    fn tampered_event_fails_verification() {
        let signer = AuditSigner::generate();
        let vk = signer.verifying_key();

        let mut event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "user:test".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "lid_tamper_test".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        signer.sign_event(&mut event);
        event.resource.id = "lid_evil".into();

        assert!(!AuditSigner::verify_event(&event, &vk));
    }

    #[test]
    fn hash_chain_links_events() {
        let signer = AuditSigner::generate();

        let mut e1 = AuditEvent::new(
            EventType::KeyCreated,
            AuditAction::CreateKey,
            AuditPrincipal {
                id: "u:a".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "k1".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );
        signer.sign_event(&mut e1);

        let expected_next_hash = {
            let sig_hex = e1.signature.as_ref().unwrap();
            let hash = blake3::hash(sig_hex.as_bytes());
            hex_encode(hash.as_bytes())
        };

        let mut e2 = AuditEvent::new(
            EventType::KeyCreated,
            AuditAction::CreateKey,
            AuditPrincipal {
                id: "u:a".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "k2".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );
        signer.sign_event(&mut e2);

        assert_eq!(
            e2.previous_hash.as_deref(),
            Some(expected_next_hash.as_str())
        );
    }

    #[test]
    fn unsigned_event_fails_verification() {
        let signer = AuditSigner::generate();
        let vk = signer.verifying_key();

        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Decrypt,
            AuditPrincipal {
                id: "u:x".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "k".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        assert!(!AuditSigner::verify_event(&event, &vk));
    }

    #[tokio::test]
    async fn signing_sink_signs_before_forwarding() {
        let (inner, events) = CollectorSink::new();
        let signer = AuditSigner::generate();
        let vk = signer.verifying_key();
        let signing_sink = SigningAuditSink::new(Box::new(inner), signer);

        let event = AuditEvent::new(
            EventType::CryptoOperation,
            AuditAction::Encrypt,
            AuditPrincipal {
                id: "u:sink".into(),
                principal_type: "User".into(),
            },
            AuditResource {
                id: "k_sink".into(),
                resource_type: "Key".into(),
            },
            AuditResult::Success,
        );

        signing_sink.emit(&event).await.unwrap();

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].signature.is_some());
        assert!(AuditSigner::verify_event(&captured[0], &vk));
    }
}
