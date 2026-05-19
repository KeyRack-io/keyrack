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

//! Domain service layer: protocol-agnostic business logic.
//!
//! Both gRPC and REST handlers delegate to functions in this module.
//! This eliminates behavioral divergence between the two API surfaces
//! (Issue 3 / Option A from the project conclusion plan).
//!
//! Functions here are called *inside* [`ops::execute`] /
//! [`ops::execute_rest`] closures, so PDP authorization and audit
//! emission remain structurally guaranteed by the ops layer.

use crate::state::ServiceState;
use keyrack_core::key::{KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord};
use keyrack_core::lid::Lid;
use keyrack_core::storage::{KeyFilter, Page};
use std::collections::HashSet;
use std::sync::Arc;

// ── Error type ──────────────────────────────────────────────────────

/// Protocol-agnostic error produced by domain functions.
///
/// Handlers map this to `tonic::Status` (gRPC) or
/// `(StatusCode, Json<Value>)` (REST) via the conversion methods.
#[derive(Debug)]
pub enum DomainError {
    NotFound(String),
    InvalidArgument(String),
    FailedPrecondition(String),
    ProviderUnavailable(String),
    Internal(String),
    Core(keyrack_core::error::KeyRackError),
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::FailedPrecondition(msg) => write!(f, "failed precondition: {msg}"),
            Self::ProviderUnavailable(msg) => write!(f, "provider unavailable: {msg}"),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
            Self::Core(e) => write!(f, "{e}"),
        }
    }
}

impl From<keyrack_core::error::KeyRackError> for DomainError {
    fn from(e: keyrack_core::error::KeyRackError) -> Self {
        use keyrack_core::error::KeyRackError;
        match &e {
            KeyRackError::KeyNotFound(_) => Self::NotFound(e.to_string()),
            KeyRackError::Storage(msg) if msg.contains("not found") => {
                Self::NotFound(e.to_string())
            }
            KeyRackError::InvalidStateTransition { .. }
            | KeyRackError::OperationNotPermitted { .. } => {
                Self::FailedPrecondition(e.to_string())
            }
            KeyRackError::ImmutableTag { .. }
            | KeyRackError::EncryptionContextMismatch
            | KeyRackError::DepthLimitExceeded { .. }
            | KeyRackError::CycleDetected { .. } => Self::InvalidArgument(e.to_string()),
            KeyRackError::ProviderUnavailable(_) => Self::ProviderUnavailable(e.to_string()),
            _ => Self::Internal(e.to_string()),
        }
    }
}

impl DomainError {
    pub fn to_grpc_status(&self) -> tonic::Status {
        match self {
            Self::NotFound(msg) => tonic::Status::not_found(msg),
            Self::InvalidArgument(msg) => tonic::Status::invalid_argument(msg),
            Self::FailedPrecondition(msg) => tonic::Status::failed_precondition(msg),
            Self::ProviderUnavailable(msg) => tonic::Status::unavailable(msg),
            Self::Internal(msg) => tonic::Status::internal(msg),
            Self::Core(e) => {
                use keyrack_core::error::KeyRackError;
                let msg = e.to_string();
                match e {
                    KeyRackError::KeyNotFound(_) => tonic::Status::not_found(msg),
                    KeyRackError::OptimisticConcurrencyConflict { .. } => tonic::Status::aborted(msg),
                    KeyRackError::InvalidStateTransition { .. }
                    | KeyRackError::OperationNotPermitted { .. }
                    | KeyRackError::ImmutableTag { .. }
                    | KeyRackError::DepthLimitExceeded { .. }
                    | KeyRackError::CycleDetected { .. } => tonic::Status::failed_precondition(msg),
                    KeyRackError::EncryptionContextMismatch => tonic::Status::invalid_argument(msg),
                    KeyRackError::AuthorizationDenied { .. } => tonic::Status::permission_denied(msg),
                    KeyRackError::ProviderUnavailable(_) => tonic::Status::unavailable(msg),
                    _ => tonic::Status::internal(msg),
                }
            }
        }
    }

    pub fn to_rest_error(&self) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        use axum::http::StatusCode;
        let (code, kind) = match self {
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
            Self::InvalidArgument(_) => (StatusCode::BAD_REQUEST, "InvalidArgument"),
            Self::FailedPrecondition(_) => (StatusCode::CONFLICT, "FailedPrecondition"),
            Self::ProviderUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "ProviderUnavailable"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
            Self::Core(e) => {
                use keyrack_core::error::KeyRackError;
                match e {
                    KeyRackError::KeyNotFound(_) => (StatusCode::NOT_FOUND, "KeyNotFound"),
                    KeyRackError::OptimisticConcurrencyConflict { .. } => (StatusCode::CONFLICT, "OccConflict"),
                    KeyRackError::InvalidStateTransition { .. } => (StatusCode::CONFLICT, "InvalidStateTransition"),
                    KeyRackError::OperationNotPermitted { .. } => (StatusCode::FORBIDDEN, "OperationNotPermitted"),
                    KeyRackError::ImmutableTag { .. } => (StatusCode::BAD_REQUEST, "ImmutableTag"),
                    KeyRackError::EncryptionContextMismatch => (StatusCode::BAD_REQUEST, "EncryptionContextMismatch"),
                    KeyRackError::AuthorizationDenied { .. } => (StatusCode::FORBIDDEN, "AuthorizationDenied"),
                    KeyRackError::ProviderUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "ProviderUnavailable"),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                }
            }
        };
        crate::ops::rest_error(code, kind, &self.to_string())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_lid(s: &str) -> Result<Lid, DomainError> {
    s.parse()
        .map_err(|_| DomainError::InvalidArgument(format!("invalid key_id: {s}")))
}

fn transition_err(from: KeyState, to: KeyState) -> DomainError {
    DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
}

/// Generate a unique LID for a new key.
///
/// Seeds the attribute set with a UUID so that every `CreateKey` call
/// produces a distinct LID even when the caller supplies no identity
/// attributes.
pub fn generate_key_lid() -> (Lid, keyrack_core::attr::AttributeSet) {
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical = keyrack_core::canon::canonicalize(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &attrs,
    );
    let lid = Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    (lid, attrs)
}

// ── Key lifecycle ───────────────────────────────────────────────────

pub struct CreateKeyInput {
    pub key_spec: KeySpec,
    pub description: Option<String>,
    pub parent_key_id: Option<String>,
}

pub async fn create_key(
    state: &Arc<ServiceState>,
    input: CreateKeyInput,
) -> Result<KeyRecord, DomainError> {
    if matches!(
        &input.key_spec,
        KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 } | KeySpec::RsaPssSha256 { key_size: 2048 }
    ) {
        tracing::warn!(
            "RSA-2048 provides only 112-bit security and is deprecated per NIST guidance (2030 deadline). \
             Consider RSA-3072+ or ECDSA P-256 for new keys."
        );
    }

    let handle = state
        .provider
        .generate_key(&input.key_spec)
        .await
        .map_err(DomainError::from)?;

    let (lid, attrs) = generate_key_lid();

    let parent_lid = input
        .parent_key_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_lid)
        .transpose()?;

    let now = chrono::Utc::now();
    let key_usage = match input.key_spec {
        KeySpec::Aes256 => KeyUsage::EncryptDecrypt,
        _ => KeyUsage::SignVerify,
    };

    let record = KeyRecord {
        lid,
        canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
        parent_lid,
        occ_version: 1,
        current_key_version: 1,
        state: KeyState::Enabled,
        key_usage,
        key_spec: input.key_spec,
        origin: keyrack_core::key::KeyOrigin::KeyRack,
        provider_class: state.provider_class,
        identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
        user_tags: keyrack_core::tags::UserTags::new(),
        created_at: now,
        updated_at: now,
        scheduled_deletion_at: None,
        description: input.description.unwrap_or_default(),
        key_versions: vec![KeyVersionRecord {
            version_number: 1,
            key_handle: handle,
            created_at: now,
            is_primary: true,
        }],
    };

    state
        .storage
        .create_key(&record)
        .await
        .map_err(DomainError::from)?;

    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats.publish_key_created(&lid).await {
            tracing::warn!(lid = %lid, error = %e, "NATS key-created publish failed");
        }
    }

    Ok(record)
}

pub async fn get_key(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    state
        .storage
        .get_key(&lid)
        .await
        .map_err(DomainError::from)
}

pub struct UpdateKeyInput {
    pub key_id: String,
    pub description: Option<String>,
}

pub async fn update_key(
    state: &Arc<ServiceState>,
    input: UpdateKeyInput,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(&input.key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    if let Some(desc) = input.description {
        record.description = desc;
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    Ok(record)
}

pub struct ListKeysInput {
    pub limit: u32,
    pub cursor: Option<String>,
}

pub async fn list_keys(
    state: &Arc<ServiceState>,
    input: ListKeysInput,
) -> Result<Page<KeyRecord>, DomainError> {
    let limit = if input.limit == 0 { 100 } else { input.limit };
    let filter = KeyFilter {
        user_tags: vec![],
        state: None,
        limit: Some(limit),
        cursor: input.cursor,
    };
    state
        .storage
        .list_keys(&filter)
        .await
        .map_err(DomainError::from)
}

pub async fn enable_key(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let old_state = record.state.to_string();
    record
        .transition_to(KeyState::Enabled)
        .map_err(|(f, t)| transition_err(f, t))?;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats.publish_state_changed(&lid, &old_state, "enabled").await {
            tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
        }
    }
    Ok(record)
}

pub struct DisableKeyResult {
    pub record: KeyRecord,
    pub cascade_count: u64,
}

pub async fn disable_key(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<DisableKeyResult, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let old_state = record.state.to_string();
    record
        .transition_to(KeyState::Disabled)
        .map_err(|(f, t)| transition_err(f, t))?;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;

    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats.publish_state_changed(&lid, &old_state, "disabled").await {
            tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
        }
    }

    // Cascade: disable all descendant keys (BFS)
    let cascade_start = std::time::Instant::now();
    let mut cascade_count = 0u64;
    let mut queue = vec![lid];
    while let Some(parent) = queue.pop() {
        let children = state
            .storage
            .list_children(&parent)
            .await
            .map_err(DomainError::from)?;
        for mut child in children {
            if child.state == KeyState::Enabled
                && child.transition_to(KeyState::Disabled).is_ok()
            {
                if let Err(e) = state.storage.update_key(&child).await {
                    tracing::error!(
                        child_lid = %child.lid,
                        error = %e,
                        "failed to disable descendant key during cascade"
                    );
                    return Err(DomainError::Internal(format!(
                        "cascade disable failed on descendant {}: {e}",
                        child.lid
                    )));
                }
                cascade_count += 1;
                queue.push(child.lid);
            }
        }
    }

    if cascade_count > 0 {
        tracing::info!(
            root = %key_id,
            descendants_disabled = cascade_count,
            elapsed_ms = cascade_start.elapsed().as_millis(),
            "cascade disable completed"
        );
        state
            .emit_audit_event(key_id, &format!("disabled {cascade_count} descendant(s)"))
            .await;
    }

    Ok(DisableKeyResult {
        record,
        cascade_count,
    })
}

pub async fn schedule_key_deletion(
    state: &Arc<ServiceState>,
    key_id: &str,
    grace_period_days: u32,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let days = if grace_period_days == 0 { 7 } else { grace_period_days };
    record
        .transition_to(KeyState::PendingDeletion)
        .map_err(|(f, t)| transition_err(f, t))?;
    record.scheduled_deletion_at =
        Some(chrono::Utc::now() + chrono::Duration::days(i64::from(days)));
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    Ok(record)
}

pub async fn cancel_key_deletion(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    if record.state != KeyState::PendingDeletion {
        return Err(DomainError::FailedPrecondition(
            "can only cancel deletion from PendingDeletion".into(),
        ));
    }
    record
        .transition_to(KeyState::Disabled)
        .map_err(|(f, t)| transition_err(f, t))?;
    record.scheduled_deletion_at = None;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    Ok(record)
}

pub async fn report_key_compromise(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<KeyRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let old_state = record.state.to_string();
    record
        .transition_to(KeyState::Compromised)
        .map_err(|(f, t)| transition_err(f, t))?;
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats
            .publish_state_changed(&lid, &old_state, "compromised")
            .await
        {
            tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
        }
    }
    Ok(record)
}

pub struct RotateKeyResult {
    pub record: KeyRecord,
    pub new_version: u64,
    pub jobs_created: usize,
}

pub async fn rotate_key(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<RotateKeyResult, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    if record.state != KeyState::Enabled {
        return Err(DomainError::FailedPrecondition(
            "key must be Enabled to rotate".into(),
        ));
    }

    let new_handle = state
        .provider
        .generate_key(&record.key_spec)
        .await
        .map_err(DomainError::from)?;
    let new_version = record.current_key_version + 1;
    for v in &mut record.key_versions {
        v.is_primary = false;
    }
    record.key_versions.push(KeyVersionRecord {
        version_number: new_version,
        key_handle: new_handle,
        created_at: chrono::Utc::now(),
        is_primary: true,
    });
    record.current_key_version = new_version;
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;

    // Create rotation jobs for all descendant keys (BFS)
    let mut queue = vec![lid];
    let mut visited = HashSet::new();
    visited.insert(lid);
    let mut total_jobs = 0usize;
    while let Some(parent_lid) = queue.pop() {
        let children = state
            .storage
            .list_children(&parent_lid)
            .await
            .map_err(DomainError::from)?;
        for dep in &children {
            if !visited.insert(dep.lid) {
                continue;
            }
            let job = keyrack_core::rotation::RotationJob::new(
                uuid::Uuid::new_v4().to_string(),
                lid,
                dep.lid,
                new_version,
            );
            if let Err(e) = state.storage.create_rotation_job(&job).await {
                tracing::warn!(
                    parent = %lid,
                    dependent = %dep.lid,
                    error = %e,
                    "failed to create rotation job for dependent"
                );
            }
            total_jobs += 1;
            queue.push(dep.lid);
        }
    }
    if total_jobs > 0 {
        tracing::info!(
            key = %key_id,
            new_version,
            jobs_created = total_jobs,
            "rotation jobs created for descendants (recursive)"
        );
    }

    if let Some(nats) = &state.nats_publisher {
        if let Err(e) = nats.publish_rotation_started(&lid, new_version).await {
            tracing::warn!(lid = %lid, error = %e, "NATS rotation-started publish failed");
        }
    }

    Ok(RotateKeyResult {
        record,
        new_version,
        jobs_created: total_jobs,
    })
}

// ── Crypto operations ───────────────────────────────────────────────

#[cfg(feature = "crypto-endpoints")]
pub mod crypto {
    use super::{parse_lid, DomainError, ServiceState};
    use keyrack_core::encryption_context::EncryptionContext;
    use keyrack_core::header::CiphertextHeader;
    use keyrack_core::key::KeySpec;
    use keyrack_core::provider::SigningAlgorithm;
    use std::sync::Arc;

    pub struct EncryptInput {
        pub key_id: String,
        pub plaintext: Vec<u8>,
        pub encryption_context: Option<EncryptionContext>,
    }

    pub struct EncryptOutput {
        pub ciphertext_blob: Vec<u8>,
        pub key_id: String,
        pub key_version: u64,
    }

    pub async fn encrypt(
        state: &Arc<ServiceState>,
        input: EncryptInput,
    ) -> Result<EncryptOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;

        if !record.state.permits_encrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — encrypt not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let ec_aad = input
            .encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();

        let ec_hash = input
            .encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        let header = CiphertextHeader::new(record.lid, record.current_key_version, ec_hash);
        let aad = header.build_aad(&ec_aad);

        let output = state
            .provider
            .encrypt(&primary.key_handle, &input.plaintext, &aad)
            .await
            .map_err(DomainError::from)?;

        let ciphertext_blob = header.wrap_payload(&output.ciphertext);

        Ok(EncryptOutput {
            ciphertext_blob,
            key_id: record.lid.to_string(),
            key_version: record.current_key_version,
        })
    }

    pub struct DecryptInput {
        pub key_id: String,
        pub ciphertext_blob: Vec<u8>,
        pub encryption_context: Option<EncryptionContext>,
    }

    pub struct DecryptOutput {
        pub plaintext: Vec<u8>,
        pub key_id: String,
    }

    pub async fn decrypt(
        state: &Arc<ServiceState>,
        input: DecryptInput,
    ) -> Result<DecryptOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;

        if !record.state.permits_decrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — decrypt not permitted",
                input.key_id, record.state
            )));
        }

        let (header, ciphertext) = CiphertextHeader::unwrap_payload(&input.ciphertext_blob)
            .map_err(|e| DomainError::InvalidArgument(e.to_string()))?;

        let ec_hash = input
            .encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        if ec_hash != header.encryption_context_hash {
            return Err(DomainError::InvalidArgument(
                "encryption context mismatch".into(),
            ));
        }

        let version_handle = record
            .key_versions
            .iter()
            .find(|v| v.version_number == header.key_version)
            .map(|v| &v.key_handle)
            .ok_or_else(|| DomainError::NotFound("key version not found".into()))?;

        let ec_aad = input
            .encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();

        let aad = header.build_aad(&ec_aad);

        let plaintext = state
            .provider
            .decrypt(version_handle, ciphertext, &aad)
            .await
            .map_err(DomainError::from)?;

        Ok(DecryptOutput {
            plaintext: plaintext.expose().clone(),
            key_id: record.lid.to_string(),
        })
    }

    pub struct ReEncryptInput {
        pub source_key_id: String,
        pub destination_key_id: String,
        pub ciphertext_blob: Vec<u8>,
        pub source_encryption_context: Option<EncryptionContext>,
        pub destination_encryption_context: Option<EncryptionContext>,
    }

    pub struct ReEncryptOutput {
        pub ciphertext_blob: Vec<u8>,
        pub source_key_id: String,
        pub destination_key_id: String,
    }

    pub async fn re_encrypt(
        state: &Arc<ServiceState>,
        input: ReEncryptInput,
    ) -> Result<ReEncryptOutput, DomainError> {
        let src_lid = parse_lid(&input.source_key_id)?;
        let dst_lid = parse_lid(&input.destination_key_id)?;

        let src_record = state.storage.get_key(&src_lid).await.map_err(DomainError::from)?;
        let dst_record = state.storage.get_key(&dst_lid).await.map_err(DomainError::from)?;

        let (header, ciphertext) = CiphertextHeader::unwrap_payload(&input.ciphertext_blob)
            .map_err(|e| DomainError::InvalidArgument(e.to_string()))?;

        let src_version = src_record
            .key_versions
            .iter()
            .find(|v| v.version_number == header.key_version)
            .ok_or_else(|| DomainError::NotFound("source key version not found".into()))?;

        let src_ec_aad = input
            .source_encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let src_aad = header.build_aad(&src_ec_aad);

        let plaintext = state
            .provider
            .decrypt(&src_version.key_handle, ciphertext, &src_aad)
            .await
            .map_err(DomainError::from)?;

        let dst_primary = dst_record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("destination has no primary version".into()))?;

        let dst_ec_hash = input
            .destination_encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        let new_header = CiphertextHeader::new(
            dst_record.lid,
            dst_record.current_key_version,
            dst_ec_hash,
        );

        let dst_ec_aad = input
            .destination_encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();
        let dst_aad = new_header.build_aad(&dst_ec_aad);

        let output = state
            .provider
            .encrypt(&dst_primary.key_handle, plaintext.expose(), &dst_aad)
            .await
            .map_err(DomainError::from)?;

        Ok(ReEncryptOutput {
            ciphertext_blob: new_header.wrap_payload(&output.ciphertext),
            source_key_id: src_record.lid.to_string(),
            destination_key_id: dst_record.lid.to_string(),
        })
    }

    pub struct SignInput {
        pub key_id: String,
        pub message: Vec<u8>,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub struct SignOutput {
        pub signature: Vec<u8>,
        pub key_id: String,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub async fn sign(
        state: &Arc<ServiceState>,
        input: SignInput,
    ) -> Result<SignOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;

        if !record.state.permits_encrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — sign not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let signature = state
            .provider
            .sign(&primary.key_handle, input.signing_algorithm, &input.message)
            .await
            .map_err(DomainError::from)?;

        Ok(SignOutput {
            signature,
            key_id: record.lid.to_string(),
            signing_algorithm: input.signing_algorithm,
        })
    }

    pub struct VerifyInput {
        pub key_id: String,
        pub message: Vec<u8>,
        pub signature: Vec<u8>,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub struct VerifyOutput {
        pub signature_valid: bool,
        pub key_id: String,
        pub signing_algorithm: SigningAlgorithm,
    }

    pub async fn verify(
        state: &Arc<ServiceState>,
        input: VerifyInput,
    ) -> Result<VerifyOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;

        if !record.state.permits_decrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — verify not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let valid = state
            .provider
            .verify(
                &primary.key_handle,
                input.signing_algorithm,
                &input.message,
                &input.signature,
            )
            .await
            .map_err(DomainError::from)?;

        Ok(VerifyOutput {
            signature_valid: valid,
            key_id: record.lid.to_string(),
            signing_algorithm: input.signing_algorithm,
        })
    }

    pub struct GenerateDataKeyInput {
        pub key_id: String,
        pub key_spec: Option<KeySpec>,
        pub number_of_bytes: u32,
        pub encryption_context: Option<EncryptionContext>,
    }

    pub struct GenerateDataKeyOutput {
        pub plaintext: Vec<u8>,
        pub ciphertext_blob: Vec<u8>,
        pub key_id: String,
    }

    pub async fn generate_data_key(
        state: &Arc<ServiceState>,
        input: GenerateDataKeyInput,
    ) -> Result<GenerateDataKeyOutput, DomainError> {
        let lid = parse_lid(&input.key_id)?;
        let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;

        if !record.state.permits_encrypt() {
            return Err(DomainError::FailedPrecondition(format!(
                "key {} is in state {} — generate data key not permitted",
                input.key_id, record.state
            )));
        }

        let primary = record
            .key_versions
            .iter()
            .find(|v| v.is_primary)
            .ok_or_else(|| DomainError::Internal("no primary key version".into()))?;

        let ec_aad = input
            .encryption_context
            .as_ref()
            .map(EncryptionContext::to_aad_bytes)
            .unwrap_or_default();

        let ec_hash = input
            .encryption_context
            .as_ref()
            .map_or([0u8; 32], EncryptionContext::hash);

        let header = CiphertextHeader::new(record.lid, record.current_key_version, ec_hash);
        let aad = header.build_aad(&ec_aad);

        let dek_len = dek_length(input.key_spec.as_ref(), input.number_of_bytes);

        let output = state
            .provider
            .generate_data_key(&primary.key_handle, dek_len, &aad)
            .await
            .map_err(DomainError::from)?;

        Ok(GenerateDataKeyOutput {
            plaintext: output.plaintext_key.into_inner(),
            ciphertext_blob: header.wrap_payload(&output.encrypted_key),
            key_id: record.lid.to_string(),
        })
    }

    pub struct GenerateDataKeyWithoutPlaintextOutput {
        pub ciphertext_blob: Vec<u8>,
        pub key_id: String,
    }

    pub async fn generate_data_key_without_plaintext(
        state: &Arc<ServiceState>,
        input: GenerateDataKeyInput,
    ) -> Result<GenerateDataKeyWithoutPlaintextOutput, DomainError> {
        let out = generate_data_key(state, input).await?;
        Ok(GenerateDataKeyWithoutPlaintextOutput {
            ciphertext_blob: out.ciphertext_blob,
            key_id: out.key_id,
        })
    }

    pub async fn generate_random(
        state: &Arc<ServiceState>,
        length: usize,
    ) -> Result<Vec<u8>, DomainError> {
        let random = state
            .provider
            .generate_random(length)
            .await
            .map_err(DomainError::from)?;
        Ok(random.into_inner())
    }

    /// Determine DEK length from an optional key spec or explicit byte count.
    fn dek_length(spec: Option<&KeySpec>, number_of_bytes: u32) -> usize {
        if number_of_bytes > 0 {
            return number_of_bytes as usize;
        }
        match spec {
            Some(
                KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 }
                | KeySpec::RsaPssSha256 { key_size: 2048 },
            ) => 256,
            Some(
                KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 }
                | KeySpec::RsaPssSha256 { key_size: 3072 },
            ) => 384,
            Some(
                KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 }
                | KeySpec::RsaPssSha256 { key_size: 4096 },
            ) => 512,
            _ => 32,
        }
    }
}

// ── Key versions ────────────────────────────────────────────────────

pub async fn list_key_versions(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<KeyVersionRecord>, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    Ok(record.key_versions)
}

pub async fn get_key_version(
    state: &Arc<ServiceState>,
    key_id: &str,
    version: u64,
) -> Result<KeyVersionRecord, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    record
        .key_versions
        .into_iter()
        .find(|v| v.version_number == version)
        .ok_or_else(|| DomainError::NotFound(format!("version {version} not found")))
}

// ── Rotation policy ─────────────────────────────────────────────────

pub async fn enable_key_rotation(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    record.user_tags.set("_keyrack_rotation_enabled", "true");
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    tracing::info!(key_id, "rotation enabled");
    Ok(())
}

pub async fn disable_key_rotation(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    record.user_tags.set("_keyrack_rotation_enabled", "false");
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    tracing::info!(key_id, "rotation disabled");
    Ok(())
}

pub struct RotationStatus {
    pub rotation_enabled: bool,
    pub last_rotated_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn get_key_rotation_status(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<RotationStatus, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let rotation_enabled = record.user_tags.get("_keyrack_rotation_enabled") == Some("true");
    let last_rotated_at = record
        .key_versions
        .iter()
        .filter(|v| !v.is_primary)
        .max_by_key(|v| v.version_number)
        .map(|v| v.created_at);
    Ok(RotationStatus {
        rotation_enabled,
        last_rotated_at,
    })
}

pub struct RotationHistoryEntry {
    pub from_version: u64,
    pub to_version: u64,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
}

pub async fn get_key_rotation_history(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<RotationHistoryEntry>, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let mut sorted = record.key_versions;
    sorted.sort_by_key(|v| v.version_number);
    let entries = sorted
        .windows(2)
        .map(|w| RotationHistoryEntry {
            from_version: w[0].version_number,
            to_version: w[1].version_number,
            rotated_at: w[1].created_at,
        })
        .collect();
    Ok(entries)
}

pub struct RotationPolicy {
    pub enabled: bool,
    pub rotation_interval_days: u32,
}

pub async fn get_key_rotation_policy(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<RotationPolicy, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let enabled = record.user_tags.get("_keyrack_rotation_enabled") == Some("true");
    let rotation_interval_days = record
        .user_tags
        .get("_keyrack_rotation_interval_days")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(RotationPolicy {
        enabled,
        rotation_interval_days,
    })
}

pub async fn set_key_rotation_policy(
    state: &Arc<ServiceState>,
    key_id: &str,
    policy: RotationPolicy,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let enabled_str = if policy.enabled { "true" } else { "false" };
    record
        .user_tags
        .set("_keyrack_rotation_enabled", enabled_str);
    record.user_tags.set(
        "_keyrack_rotation_interval_days",
        policy.rotation_interval_days.to_string(),
    );
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)?;
    tracing::info!(
        key_id,
        enabled = policy.enabled,
        interval_days = policy.rotation_interval_days,
        "rotation policy persisted"
    );
    Ok(())
}

// ── Hierarchy queries ───────────────────────────────────────────────

pub struct LineageEntry {
    pub id: String,
    pub resource_type: String,
    pub depth: u32,
    pub parent_id: Option<String>,
}

pub async fn get_key_dependents(
    state: &Arc<ServiceState>,
    key_id: &str,
    recursive: bool,
) -> Result<Vec<LineageEntry>, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut dependents = Vec::new();
    let mut queue = vec![(lid, 1u32)];
    let mut visited = HashSet::new();
    visited.insert(lid);

    while let Some((parent_lid, depth)) = queue.pop() {
        let children = state
            .storage
            .list_children(&parent_lid)
            .await
            .map_err(DomainError::from)?;
        for child in &children {
            if !visited.insert(child.lid) {
                continue;
            }
            dependents.push(LineageEntry {
                id: child.lid.to_string(),
                resource_type: "key".into(),
                depth,
                parent_id: Some(parent_lid.to_string()),
            });
            if recursive {
                queue.push((child.lid, depth + 1));
            }
        }
    }
    Ok(dependents)
}

pub async fn get_key_ancestors(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<LineageEntry>, DomainError> {
    let lid = parse_lid(key_id)?;
    let mut ancestors = Vec::new();
    let mut current = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    let mut depth = 1u32;
    let mut visited = HashSet::new();
    visited.insert(lid);

    while let Some(parent_lid) = current.parent_lid {
        if !visited.insert(parent_lid) {
            break;
        }
        current = state
            .storage
            .get_key(&parent_lid)
            .await
            .map_err(DomainError::from)?;
        ancestors.push(LineageEntry {
            id: parent_lid.to_string(),
            resource_type: "key".into(),
            depth,
            parent_id: current.parent_lid.map(|l| l.to_string()),
        });
        depth += 1;
        if depth > 100 {
            break;
        }
    }
    Ok(ancestors)
}

// ── Aliases ─────────────────────────────────────────────────────────

pub async fn create_alias(
    state: &Arc<ServiceState>,
    alias_name: &str,
    target_key_id: &str,
) -> Result<keyrack_core::storage::AliasRecord, DomainError> {
    let lid = parse_lid(target_key_id)?;
    let alias = keyrack_core::storage::AliasRecord {
        alias_name: alias_name.to_owned(),
        target_lid: lid,
        created_at: chrono::Utc::now(),
    };
    state
        .storage
        .create_alias(&alias)
        .await
        .map_err(DomainError::from)?;
    Ok(alias)
}

pub async fn delete_alias(
    state: &Arc<ServiceState>,
    alias_name: &str,
) -> Result<(), DomainError> {
    state
        .storage
        .delete_alias(alias_name)
        .await
        .map_err(DomainError::from)
}

pub async fn list_aliases(
    state: &Arc<ServiceState>,
) -> Result<Vec<keyrack_core::storage::AliasRecord>, DomainError> {
    state.storage.list_aliases().await.map_err(DomainError::from)
}

// ── Tags ────────────────────────────────────────────────────────────

pub async fn tag_resource(
    state: &Arc<ServiceState>,
    key_id: &str,
    tags: Vec<(String, String)>,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    for (k, v) in tags {
        record.user_tags.set(k, v);
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)
}

pub async fn untag_resource(
    state: &Arc<ServiceState>,
    key_id: &str,
    tag_keys: Vec<String>,
) -> Result<(), DomainError> {
    let lid = parse_lid(key_id)?;
    let mut record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    for key in &tag_keys {
        record.user_tags.remove(key);
    }
    record.occ_version += 1;
    record.updated_at = chrono::Utc::now();
    state
        .storage
        .update_key(&record)
        .await
        .map_err(DomainError::from)
}

pub async fn list_resource_tags(
    state: &Arc<ServiceState>,
    key_id: &str,
) -> Result<Vec<(String, String)>, DomainError> {
    let lid = parse_lid(key_id)?;
    let record = state.storage.get_key(&lid).await.map_err(DomainError::from)?;
    Ok(record
        .user_tags
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

// ── HSM connections ─────────────────────────────────────────────────

pub async fn create_hsm_connection(
    state: &Arc<ServiceState>,
    provider_type: keyrack_core::hsm::HsmProviderType,
    endpoint: &str,
) -> Result<keyrack_core::hsm::HsmConnection, DomainError> {
    let conn = keyrack_core::hsm::HsmConnection::new(
        uuid::Uuid::new_v4().to_string(),
        provider_type,
        endpoint,
        "",
    );
    state
        .storage
        .create_hsm_connection(&conn)
        .await
        .map_err(DomainError::from)?;
    Ok(conn)
}

pub async fn get_hsm_connection(
    state: &Arc<ServiceState>,
    connection_id: &str,
) -> Result<keyrack_core::hsm::HsmConnection, DomainError> {
    state
        .storage
        .get_hsm_connection(connection_id)
        .await
        .map_err(DomainError::from)
}

pub async fn list_hsm_connections(
    state: &Arc<ServiceState>,
) -> Result<Vec<keyrack_core::hsm::HsmConnection>, DomainError> {
    state
        .storage
        .list_hsm_connections()
        .await
        .map_err(DomainError::from)
}

pub async fn delete_hsm_connection(
    state: &Arc<ServiceState>,
    connection_id: &str,
) -> Result<(), DomainError> {
    state
        .storage
        .delete_hsm_connection(connection_id)
        .await
        .map_err(DomainError::from)
}

pub async fn get_hsm_connection_status(
    state: &Arc<ServiceState>,
    connection_id: &str,
) -> Result<keyrack_core::hsm::HsmConnection, DomainError> {
    state
        .storage
        .get_hsm_connection(connection_id)
        .await
        .map_err(DomainError::from)
}

// ── Rotation jobs ───────────────────────────────────────────────────

pub async fn list_rotation_jobs(
    state: &Arc<ServiceState>,
    state_filter: Option<keyrack_core::rotation::RotationJobState>,
    key_id: Option<&str>,
) -> Result<Vec<keyrack_core::rotation::RotationJob>, DomainError> {
    let key_filter_lid = key_id.map(parse_lid).transpose()?;
    let mut jobs = state
        .storage
        .list_rotation_jobs(state_filter)
        .await
        .map_err(DomainError::from)?;
    if let Some(lid) = &key_filter_lid {
        jobs.retain(|j| j.parent_lid == *lid || j.dependent_lid == *lid);
    }
    Ok(jobs)
}

pub async fn acknowledge_rotation_job(
    state: &Arc<ServiceState>,
    job_id: &str,
) -> Result<keyrack_core::rotation::RotationJob, DomainError> {
    let mut job = state
        .storage
        .get_rotation_job(job_id)
        .await
        .map_err(DomainError::from)?;
    job.transition_to(keyrack_core::rotation::RotationJobState::Acknowledged)
        .map_err(|(from, to)| {
            DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
        })?;
    state
        .storage
        .update_rotation_job(&job)
        .await
        .map_err(DomainError::from)?;
    Ok(job)
}

pub async fn complete_rotation_job(
    state: &Arc<ServiceState>,
    job_id: &str,
) -> Result<keyrack_core::rotation::RotationJob, DomainError> {
    let mut job = state
        .storage
        .get_rotation_job(job_id)
        .await
        .map_err(DomainError::from)?;
    job.transition_to(keyrack_core::rotation::RotationJobState::Completed)
        .map_err(|(from, to)| {
            DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
        })?;
    state
        .storage
        .update_rotation_job(&job)
        .await
        .map_err(DomainError::from)?;
    Ok(job)
}

pub async fn fail_rotation_job(
    state: &Arc<ServiceState>,
    job_id: &str,
    reason: &str,
) -> Result<keyrack_core::rotation::RotationJob, DomainError> {
    let mut job = state
        .storage
        .get_rotation_job(job_id)
        .await
        .map_err(DomainError::from)?;
    job.fail(reason).map_err(|(from, to)| {
        DomainError::FailedPrecondition(format!("cannot transition from {from} to {to}"))
    })?;
    state
        .storage
        .update_rotation_job(&job)
        .await
        .map_err(DomainError::from)?;
    Ok(job)
}
