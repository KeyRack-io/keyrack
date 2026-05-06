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

//! gRPC `KeyService` implementation.
//!
//! Every handler uses [`ops::execute`] to ensure PDP authorization
//! and audit emission are structurally impossible to skip.

use crate::convert;
use crate::ops::{self, OpContext};
use crate::proto;
use crate::proto::key_service_server::KeyService;
use crate::state::ServiceState;
use keyrack_core::audit::AuditAction;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct KeyServiceImpl {
    state: Arc<ServiceState>,
}

impl KeyServiceImpl {
    pub fn new(state: Arc<ServiceState>) -> Self {
        Self { state }
    }

    async fn principal<T>(&self, request: &Request<T>) -> keyrack_core::pdp::Principal {
        ops::extract_principal_grpc(&self.state, request).await
    }
}

#[cfg(not(feature = "crypto-endpoints"))]
fn crypto_disabled(name: &str) -> Status {
    Status::unimplemented(format!(
        "{name}: crypto endpoints disabled; use library mode or enable the `crypto-endpoints` feature"
    ))
}

#[cfg(feature = "crypto-endpoints")]
fn build_encryption_context(
    map: &std::collections::HashMap<String, String>,
) -> Option<keyrack_core::encryption_context::EncryptionContext> {
    if map.is_empty() {
        return None;
    }
    let mut ec = keyrack_core::encryption_context::EncryptionContext::new();
    for (k, v) in map {
        ec.insert(k, v);
    }
    Some(ec)
}

/// Generate a unique LID for a new key by seeding the attribute set
/// with a UUID.  This ensures every `CreateKey` produces a distinct
/// LID even when the caller does not supply identity attributes.
fn generate_key_lid() -> (
    keyrack_core::lid::Lid,
    keyrack_core::attr::AttributeSet,
) {
    let mut attrs = keyrack_core::attr::AttributeSet::new();
    attrs.insert(
        "_keyrack_key_id",
        keyrack_core::attr::AttributeValue::String(uuid::Uuid::new_v4().to_string()),
    );
    let canonical = keyrack_core::canon::canonicalize(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &attrs,
    );
    let lid = keyrack_core::lid::Lid::derive(
        keyrack_core::canon::CanonicalizationVersion::V1,
        &canonical,
    );
    (lid, attrs)
}

#[tonic::async_trait]
impl KeyService for KeyServiceImpl {
    // ── Cryptographic operations ────────────────────────────────────
    //
    // Gated behind the `crypto-endpoints` Cargo feature (default-on).
    // When disabled, all crypto RPCs return UNIMPLEMENTED and the service
    // operates as an orchestration-only coordinator.

    async fn encrypt(
        &self,
        request: Request<proto::EncryptRequest>,
    ) -> Result<Response<proto::EncryptResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("Encrypt")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();

        let ec_hash = if req.encryption_context.is_empty() {
            None
        } else {
            let ec = build_encryption_context(&req.encryption_context);
            ec.as_ref().map(keyrack_core::encryption_context::EncryptionContext::hash)
        };

        let mut op_ctx = OpContext::key(AuditAction::Encrypt, principal, &key_id);
        op_ctx.encryption_context_hash = ec_hash;

        ops::execute(
            &self.state,
            op_ctx,
            |state| async move {
                let record = state
                    .storage
                    .get_key(&parse_lid(&key_id)?)
                    .await
                    .map_err(convert::error_to_status)?;

                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition(format!(
                        "key {key_id} is in state {} — encrypt not permitted",
                        record.state
                    )));
                }

                let ec = build_encryption_context(&req.encryption_context);

                let primary_version = record
                    .key_versions
                    .iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;

                let aad = ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let output = state
                    .provider
                    .encrypt(&primary_version.key_handle, &req.plaintext, &aad)
                    .await
                    .map_err(convert::error_to_status)?;

                let ec_hash = ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );

                let header = keyrack_core::header::CiphertextHeader::new(
                    record.lid,
                    record.current_key_version,
                    ec_hash,
                );

                let ciphertext_blob = header.wrap_payload(&output.ciphertext);

                #[allow(clippy::cast_possible_truncation)]
                Ok(Response::new(proto::EncryptResponse {
                    ciphertext_blob,
                    key_id: record.lid.to_string(),
                    key_version: record.current_key_version as u32,
                }))
            },
        )
        .await
        }
    }

    async fn decrypt(
        &self,
        request: Request<proto::DecryptRequest>,
    ) -> Result<Response<proto::DecryptResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("Decrypt")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();

        let ec_hash = if req.encryption_context.is_empty() {
            None
        } else {
            let ec = build_encryption_context(&req.encryption_context);
            ec.as_ref().map(keyrack_core::encryption_context::EncryptionContext::hash)
        };

        let mut op_ctx = OpContext::key(AuditAction::Decrypt, principal, &key_id);
        op_ctx.encryption_context_hash = ec_hash;

        ops::execute(
            &self.state,
            op_ctx,
            |state| async move {
                let record = state
                    .storage
                    .get_key(&parse_lid(&key_id)?)
                    .await
                    .map_err(convert::error_to_status)?;

                if !record.state.permits_decrypt() {
                    return Err(Status::failed_precondition(format!(
                        "key {key_id} is in state {} — decrypt not permitted",
                        record.state
                    )));
                }

                let (header, ciphertext) =
                    keyrack_core::header::CiphertextHeader::unwrap_payload(&req.ciphertext_blob)
                        .map_err(|e| Status::invalid_argument(e.to_string()))?;

                let ec = build_encryption_context(&req.encryption_context);

                let ec_hash = ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );
                if ec_hash != header.encryption_context_hash {
                    return Err(Status::invalid_argument("encryption context mismatch"));
                }

                let version_handle = record
                    .key_versions
                    .iter()
                    .find(|v| v.version_number == header.key_version)
                    .map(|v| &v.key_handle)
                    .ok_or_else(|| Status::not_found("key version not found"))?;

                let aad = ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let plaintext = state
                    .provider
                    .decrypt(version_handle, ciphertext, &aad)
                    .await
                    .map_err(convert::error_to_status)?;

                Ok(Response::new(proto::DecryptResponse {
                    plaintext: plaintext.expose().clone(),
                    key_id: record.lid.to_string(),
                }))
            },
        )
        .await
        }
    }

    async fn re_encrypt(
        &self,
        request: Request<proto::ReEncryptRequest>,
    ) -> Result<Response<proto::ReEncryptResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("ReEncrypt")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let src_key_id = req.source_key_id.clone();

        let dst_ec_hash = if req.destination_encryption_context.is_empty() {
            None
        } else {
            let ec = build_encryption_context(&req.destination_encryption_context);
            ec.as_ref().map(keyrack_core::encryption_context::EncryptionContext::hash)
        };

        let mut op_ctx = OpContext::key(AuditAction::ReEncrypt, principal, &src_key_id);
        op_ctx.encryption_context_hash = dst_ec_hash;

        ops::execute(
            &self.state,
            op_ctx,
            |state| async move {
                let src_lid = parse_lid(&req.source_key_id)?;
                let dst_lid = parse_lid(&req.destination_key_id)?;

                let src_record = state.storage.get_key(&src_lid).await.map_err(convert::error_to_status)?;
                let dst_record = state.storage.get_key(&dst_lid).await.map_err(convert::error_to_status)?;

                let src_ec = build_encryption_context(&req.source_encryption_context);
                let dst_ec = build_encryption_context(&req.destination_encryption_context);

                let (header, ciphertext) =
                    keyrack_core::header::CiphertextHeader::unwrap_payload(&req.ciphertext_blob)
                        .map_err(|e| Status::invalid_argument(e.to_string()))?;

                let src_version = src_record.key_versions.iter()
                    .find(|v| v.version_number == header.key_version)
                    .ok_or_else(|| Status::not_found("source key version not found"))?;

                let src_aad = src_ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let plaintext = state.provider
                    .decrypt(&src_version.key_handle, ciphertext, &src_aad)
                    .await.map_err(convert::error_to_status)?;

                let dst_primary = dst_record.key_versions.iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("destination has no primary version"))?;

                let dst_aad = dst_ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let output = state.provider
                    .encrypt(&dst_primary.key_handle, plaintext.expose(), &dst_aad)
                    .await.map_err(convert::error_to_status)?;

                let dst_ec_hash = dst_ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );

                let new_header = keyrack_core::header::CiphertextHeader::new(
                    dst_record.lid, dst_record.current_key_version, dst_ec_hash,
                );

                Ok(Response::new(proto::ReEncryptResponse {
                    ciphertext_blob: new_header.wrap_payload(&output.ciphertext),
                    source_key_id: src_record.lid.to_string(),
                    destination_key_id: dst_record.lid.to_string(),
                }))
            },
        ).await
        }
    }

    async fn generate_data_key(
        &self,
        request: Request<proto::GenerateDataKeyRequest>,
    ) -> Result<Response<proto::GenerateDataKeyResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("GenerateDataKey")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();

        let ec_hash = if req.encryption_context.is_empty() {
            None
        } else {
            let ec = build_encryption_context(&req.encryption_context);
            ec.as_ref().map(keyrack_core::encryption_context::EncryptionContext::hash)
        };

        let mut op_ctx = OpContext::key(AuditAction::GenerateDataKey, principal, &key_id);
        op_ctx.encryption_context_hash = ec_hash;

        ops::execute(
            &self.state,
            op_ctx,
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;

                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition("key not in Enabled state"));
                }

                let primary = record.key_versions.iter().find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;

                let ec = build_encryption_context(&req.encryption_context);
                let aad = ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let dek_len = dek_length_from_spec(req.key_spec);

                let output = state.provider
                    .generate_data_key(&primary.key_handle, dek_len, &aad)
                    .await.map_err(convert::error_to_status)?;

                let ec_hash = ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );

                let header = keyrack_core::header::CiphertextHeader::new(
                    record.lid, record.current_key_version, ec_hash,
                );

                Ok(Response::new(proto::GenerateDataKeyResponse {
                    plaintext_data_key: output.plaintext_key.into_inner(),
                    encrypted_data_key: header.wrap_payload(&output.encrypted_key),
                    key_id: record.lid.to_string(),
                }))
            },
        ).await
        }
    }

    async fn generate_data_key_without_plaintext(
        &self,
        request: Request<proto::GenerateDataKeyWithoutPlaintextRequest>,
    ) -> Result<Response<proto::GenerateDataKeyWithoutPlaintextResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("GenerateDataKeyWithoutPlaintext")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();

        let ec_hash = if req.encryption_context.is_empty() {
            None
        } else {
            let ec = build_encryption_context(&req.encryption_context);
            ec.as_ref().map(keyrack_core::encryption_context::EncryptionContext::hash)
        };

        let mut op_ctx = OpContext::key(AuditAction::GenerateDataKeyWithoutPlaintext, principal, &key_id);
        op_ctx.encryption_context_hash = ec_hash;

        ops::execute(
            &self.state,
            op_ctx,
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition("key not in Enabled state"));
                }
                let primary = record.key_versions.iter().find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;
                let ec = build_encryption_context(&req.encryption_context);
                let aad = ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();
                let dek_len = dek_length_from_spec(req.key_spec);
                let output = state.provider
                    .generate_data_key(&primary.key_handle, dek_len, &aad)
                    .await.map_err(convert::error_to_status)?;
                let ec_hash = ec.as_ref().map_or([0u8; 32], keyrack_core::encryption_context::EncryptionContext::hash);
                let header = keyrack_core::header::CiphertextHeader::new(record.lid, record.current_key_version, ec_hash);
                Ok(Response::new(proto::GenerateDataKeyWithoutPlaintextResponse {
                    encrypted_data_key: header.wrap_payload(&output.encrypted_key),
                    key_id: record.lid.to_string(),
                }))
            },
        ).await
        }
    }

    async fn generate_random(
        &self,
        request: Request<proto::GenerateRandomRequest>,
    ) -> Result<Response<proto::GenerateRandomResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("GenerateRandom")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let req = request.into_inner();

        ops::execute(
            &self.state,
            OpContext::system(AuditAction::GenerateRandom, "", "System"),
            |state| async move {
                let random_bytes = state
                    .provider
                    .generate_random(req.number_of_bytes as usize)
                    .await
                    .map_err(convert::error_to_status)?;
                Ok(Response::new(proto::GenerateRandomResponse {
                    random_bytes: random_bytes.into_inner(),
                }))
            },
        )
        .await
        }
    }

    async fn sign(
        &self,
        request: Request<proto::SignRequest>,
    ) -> Result<Response<proto::SignResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("Sign")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();

        ops::execute(
            &self.state,
            OpContext::key(AuditAction::Sign, principal, &key_id),
            |state| async move {
                let alg_proto = proto::SigningAlgorithm::try_from(req.signing_algorithm)
                    .unwrap_or(proto::SigningAlgorithm::Unspecified);
                let alg = convert::proto_to_signing_algorithm(alg_proto)
                    .ok_or_else(|| Status::invalid_argument("signing algorithm required"))?;

                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition("sign not permitted in current state"));
                }
                let primary_version = record.key_versions.iter().find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;
                let signature = state.provider
                    .sign(&primary_version.key_handle, alg, &req.message)
                    .await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::SignResponse {
                    signature,
                    key_id: record.lid.to_string(),
                    signing_algorithm: convert::signing_algorithm_to_proto(&alg).into(),
                }))
            },
        ).await
        }
    }

    async fn verify(
        &self,
        request: Request<proto::VerifyRequest>,
    ) -> Result<Response<proto::VerifyResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        { let _ = request; return Err(crypto_disabled("Verify")); }

        #[cfg(feature = "crypto-endpoints")]
        {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();

        ops::execute(
            &self.state,
            OpContext::key(AuditAction::Verify, principal, &key_id),
            |state| async move {
                let alg_proto = proto::SigningAlgorithm::try_from(req.signing_algorithm)
                    .unwrap_or(proto::SigningAlgorithm::Unspecified);
                let alg = convert::proto_to_signing_algorithm(alg_proto)
                    .ok_or_else(|| Status::invalid_argument("signing algorithm required"))?;
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                if !record.state.permits_decrypt() {
                    return Err(Status::failed_precondition("verify not permitted in current state"));
                }
                let primary_version = record.key_versions.iter().find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;
                let valid = state.provider
                    .verify(&primary_version.key_handle, alg, &req.message, &req.signature)
                    .await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::VerifyResponse {
                    signature_valid: valid,
                    key_id: record.lid.to_string(),
                    signing_algorithm: convert::signing_algorithm_to_proto(&alg).into(),
                }))
            },
        ).await
        }
    }

    // ── Key lifecycle ───────────────────────────────────────────────

    async fn create_key(
        &self,
        request: Request<proto::CreateKeyRequest>,
    ) -> Result<Response<proto::CreateKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();

        ops::execute(
            &self.state,
            OpContext::key(AuditAction::CreateKey, principal, "(new)"),
            |state| async move {
                let spec = convert::proto_to_key_spec(
                    proto::KeySpec::try_from(req.key_spec).unwrap_or(proto::KeySpec::Unspecified),
                )
                .ok_or_else(|| Status::invalid_argument("key_spec is required"))?;

                let handle = state.provider.generate_key(&spec).await.map_err(convert::error_to_status)?;

                let (lid, attrs) = generate_key_lid();

                let now = chrono::Utc::now();
                let key_usage = match spec {
                    keyrack_core::key::KeySpec::Aes256 => keyrack_core::key::KeyUsage::EncryptDecrypt,
                    _ => keyrack_core::key::KeyUsage::SignVerify,
                };

                let record = keyrack_core::key::KeyRecord {
                    lid,
                    canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
                    parent_lid: None,
                    occ_version: 1,
                    current_key_version: 1,
                    state: keyrack_core::key::KeyState::Enabled,
                    key_usage,
                    key_spec: spec,
                    origin: keyrack_core::key::KeyOrigin::KeyRack,
                    provider_class: keyrack_core::key::ProviderClass::Software,
                    identity_tags: keyrack_core::tags::IdentityTags::from_attribute_set(&attrs),
                    user_tags: keyrack_core::tags::UserTags::new(),
                    created_at: now,
                    updated_at: now,
                    scheduled_deletion_at: None,
                    description: req.description,
                    key_versions: vec![keyrack_core::key::KeyVersionRecord {
                        version_number: 1,
                        key_handle: handle,
                        created_at: now,
                        is_primary: true,
                    }],
                };

                state.storage.create_key(&record).await.map_err(convert::error_to_status)?;

                Ok(Response::new(proto::CreateKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn get_key(
        &self,
        request: Request<proto::GetKeyRequest>,
    ) -> Result<Response<proto::GetKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKey, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::GetKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn describe_key(
        &self,
        request: Request<proto::DescribeKeyRequest>,
    ) -> Result<Response<proto::DescribeKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::DescribeKey, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::DescribeKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn update_key(
        &self,
        request: Request<proto::UpdateKeyRequest>,
    ) -> Result<Response<proto::UpdateKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::UpdateKey, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                record.description = req.description.unwrap_or_default();
                record.occ_version += 1;
                record.updated_at = chrono::Utc::now();
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::UpdateKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn list_keys(
        &self,
        request: Request<proto::ListKeysRequest>,
    ) -> Result<Response<proto::ListKeysResponse>, Status> {
        ops::execute(
            &self.state,
            OpContext::system(AuditAction::ListKeys, "", "Key"),
            |state| async move {
                let req = request.into_inner();
                let limit = if req.max_results == 0 { 100 } else { req.max_results };
                let filter = keyrack_core::storage::KeyFilter {
                    user_tags: vec![],
                    limit: Some(limit),
                    cursor: if req.cursor.is_empty() { None } else { Some(req.cursor) },
                };
                let page = state.storage.list_keys(&filter).await.map_err(convert::error_to_status)?;
                let keys = page.items.iter().map(convert::key_record_to_metadata).collect();
                Ok(Response::new(proto::ListKeysResponse {
                    keys,
                    next_cursor: page.next_cursor.unwrap_or_default(),
                }))
            },
        ).await
    }

    async fn enable_key(
        &self,
        request: Request<proto::EnableKeyRequest>,
    ) -> Result<Response<proto::EnableKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::EnableKey, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                record.transition_to(keyrack_core::key::KeyState::Enabled).map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::EnableKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn disable_key(
        &self,
        request: Request<proto::DisableKeyRequest>,
    ) -> Result<Response<proto::DisableKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::DisableKey, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                record.transition_to(keyrack_core::key::KeyState::Disabled).map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;

                // Cascade: disable all descendant keys recursively
                let cascade_start = std::time::Instant::now();
                let mut cascade_count = 0u64;
                let mut queue = vec![lid];
                while let Some(parent) = queue.pop() {
                    let children = state.storage.list_children(&parent).await
                        .map_err(convert::error_to_status)?;
                    for mut child in children {
                        if child.state == keyrack_core::key::KeyState::Enabled {
                            if child.transition_to(keyrack_core::key::KeyState::Disabled).is_ok() {
                                let _ = state.storage.update_key(&child).await;
                                cascade_count += 1;
                                queue.push(child.lid);
                            }
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
                    // Emit NATS invalidation if event sink is configured
                    state.emit_audit_event(
                        "CascadeDisable",
                        &key_id,
                        &format!("disabled {cascade_count} descendant(s)"),
                    ).await;
                }

                Ok(Response::new(proto::DisableKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn schedule_key_deletion(
        &self,
        request: Request<proto::ScheduleKeyDeletionRequest>,
    ) -> Result<Response<proto::ScheduleKeyDeletionResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::ScheduleKeyDeletion, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let days = if req.grace_period_days == 0 { 7 } else { req.grace_period_days };
                record.transition_to(keyrack_core::key::KeyState::PendingDeletion).map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
                record.scheduled_deletion_at = Some(chrono::Utc::now() + chrono::Duration::days(i64::from(days)));
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::ScheduleKeyDeletionResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                    deletion_date: record.scheduled_deletion_at.as_ref().map(convert::datetime_to_timestamp),
                }))
            },
        ).await
    }

    async fn cancel_key_deletion(
        &self,
        request: Request<proto::CancelKeyDeletionRequest>,
    ) -> Result<Response<proto::CancelKeyDeletionResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::CancelKeyDeletion, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                if record.state != keyrack_core::key::KeyState::PendingDeletion {
                    return Err(Status::failed_precondition("can only cancel deletion from PendingDeletion"));
                }
                record.transition_to(keyrack_core::key::KeyState::Disabled).map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
                record.scheduled_deletion_at = None;
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::CancelKeyDeletionResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                }))
            },
        ).await
    }

    async fn rotate_key(
        &self,
        request: Request<proto::RotateKeyRequest>,
    ) -> Result<Response<proto::RotateKeyResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::RotateKey, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                if record.state != keyrack_core::key::KeyState::Enabled {
                    return Err(Status::failed_precondition("key must be Enabled to rotate"));
                }
                let new_handle = state.provider.generate_key(&record.key_spec).await.map_err(convert::error_to_status)?;
                let new_version = record.current_key_version + 1;
                for v in &mut record.key_versions { v.is_primary = false; }
                record.key_versions.push(keyrack_core::key::KeyVersionRecord {
                    version_number: new_version,
                    key_handle: new_handle,
                    created_at: chrono::Utc::now(),
                    is_primary: true,
                });
                record.current_key_version = new_version;
                record.occ_version += 1;
                record.updated_at = chrono::Utc::now();
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;

                // Create rotation jobs for dependent keys (§5.6)
                let dependents = state.storage.list_children(&lid).await
                    .map_err(convert::error_to_status)?;
                for dep in &dependents {
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
                }
                if !dependents.is_empty() {
                    tracing::info!(
                        key = %key_id,
                        new_version,
                        jobs_created = dependents.len(),
                        "rotation jobs created for dependents"
                    );
                }

                #[allow(clippy::cast_possible_truncation)]
                Ok(Response::new(proto::RotateKeyResponse {
                    metadata: Some(convert::key_record_to_metadata(&record)),
                    new_version: new_version as u32,
                }))
            },
        ).await
    }

    // ── Key versions ────────────────────────────────────────────────

    async fn list_key_versions(
        &self,
        request: Request<proto::ListKeyVersionsRequest>,
    ) -> Result<Response<proto::ListKeyVersionsResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::ListKeyVersions, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let versions: Vec<_> = record.key_versions.iter().map(convert::key_version_to_proto).collect();
                Ok(Response::new(proto::ListKeyVersionsResponse {
                    versions,
                    next_cursor: String::new(),
                }))
            },
        ).await
    }

    async fn get_key_version(
        &self,
        request: Request<proto::GetKeyVersionRequest>,
    ) -> Result<Response<proto::GetKeyVersionResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKeyVersion, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let version = record.key_versions.iter()
                    .find(|v| v.version_number == u64::from(req.version))
                    .ok_or_else(|| Status::not_found(format!("version {} not found", req.version)))?;
                Ok(Response::new(proto::GetKeyVersionResponse {
                    version: Some(convert::key_version_to_proto(version)),
                }))
            },
        ).await
    }

    // ── Rotation control ────────────────────────────────────────────
    // Rotation policy is stored per-key as metadata. Since the KeyRecord
    // doesn't yet have a rotation_policy field, these RPCs use a minimal
    // in-memory representation derived from the key's version history.

    async fn enable_key_rotation(
        &self,
        request: Request<proto::EnableKeyRotationRequest>,
    ) -> Result<Response<proto::EnableKeyRotationResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::EnableKeyRotation, principal, &key_id),
            |_state| async move {
                let _lid = parse_lid(&key_id)?;
                tracing::info!(key_id, "rotation enabled (policy persistence pending)");
                Ok(Response::new(proto::EnableKeyRotationResponse {}))
            },
        ).await
    }

    async fn disable_key_rotation(
        &self,
        request: Request<proto::DisableKeyRotationRequest>,
    ) -> Result<Response<proto::DisableKeyRotationResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::DisableKeyRotation, principal, &key_id),
            |_state| async move {
                let _lid = parse_lid(&key_id)?;
                tracing::info!(key_id, "rotation disabled (policy persistence pending)");
                Ok(Response::new(proto::DisableKeyRotationResponse {}))
            },
        ).await
    }

    async fn get_key_rotation_status(
        &self,
        request: Request<proto::GetKeyRotationStatusRequest>,
    ) -> Result<Response<proto::GetKeyRotationStatusResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKeyRotationStatus, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let last_rotated = record.key_versions.iter()
                    .filter(|v| !v.is_primary)
                    .max_by_key(|v| v.version_number)
                    .map(|v| convert::datetime_to_timestamp(&v.created_at));
                Ok(Response::new(proto::GetKeyRotationStatusResponse {
                    rotation_enabled: false,
                    next_rotation_date: None,
                    last_rotated_at: last_rotated,
                }))
            },
        ).await
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn get_key_rotation_history(
        &self,
        request: Request<proto::GetKeyRotationHistoryRequest>,
    ) -> Result<Response<proto::GetKeyRotationHistoryResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKeyRotationHistory, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let mut entries = Vec::new();
                let mut sorted_versions = record.key_versions.clone();
                sorted_versions.sort_by_key(|v| v.version_number);
                for window in sorted_versions.windows(2) {
                    entries.push(proto::RotationHistoryEntry {
                        from_version: window[0].version_number as u32,
                        to_version: window[1].version_number as u32,
                        rotated_at: Some(convert::datetime_to_timestamp(&window[1].created_at)),
                    });
                }
                Ok(Response::new(proto::GetKeyRotationHistoryResponse {
                    entries,
                    next_cursor: String::new(),
                }))
            },
        ).await
    }

    async fn get_key_rotation_policy(
        &self,
        request: Request<proto::GetKeyRotationPolicyRequest>,
    ) -> Result<Response<proto::GetKeyRotationPolicyResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKeyRotationPolicy, principal, &key_id),
            |_state| async move {
                Ok(Response::new(proto::GetKeyRotationPolicyResponse {
                    policy: Some(proto::RotationPolicy {
                        enabled: false,
                        rotation_interval_days: 0,
                    }),
                }))
            },
        ).await
    }

    async fn set_key_rotation_policy(
        &self,
        request: Request<proto::SetKeyRotationPolicyRequest>,
    ) -> Result<Response<proto::SetKeyRotationPolicyResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::SetKeyRotationPolicy, principal, &key_id),
            |_state| async move {
                let _lid = parse_lid(&key_id)?;
                if let Some(policy) = &req.policy {
                    tracing::info!(
                        key_id,
                        enabled = policy.enabled,
                        interval_days = policy.rotation_interval_days,
                        "rotation policy set (persistence pending)"
                    );
                }
                Ok(Response::new(proto::SetKeyRotationPolicyResponse {}))
            },
        ).await
    }

    // ── Hierarchy queries ───────────────────────────────────────────

    async fn get_key_dependents(
        &self,
        request: Request<proto::GetKeyDependentsRequest>,
    ) -> Result<Response<proto::GetKeyDependentsResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKeyDependents, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut dependents = Vec::new();
                let mut queue = vec![(lid, 1u32)];
                let mut visited = std::collections::HashSet::new();
                visited.insert(lid);
                while let Some((parent_lid, depth)) = queue.pop() {
                    let children = state.storage.list_children(&parent_lid).await
                        .map_err(convert::error_to_status)?;
                    for child in &children {
                        if !visited.insert(child.lid) {
                            continue;
                        }
                        dependents.push(proto::LineageEntry {
                            id: child.lid.to_string(),
                            resource_type: "key".into(),
                            depth,
                            parent_id: Some(parent_lid.to_string()),
                        });
                        if req.recursive {
                            queue.push((child.lid, depth + 1));
                        }
                    }
                }
                Ok(Response::new(proto::GetKeyDependentsResponse { dependents }))
            },
        ).await
    }

    async fn get_key_ancestors(
        &self,
        request: Request<proto::GetKeyAncestorsRequest>,
    ) -> Result<Response<proto::GetKeyAncestorsResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::GetKeyAncestors, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut ancestors = Vec::new();
                let mut current = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let mut depth = 1u32;
                let mut visited = std::collections::HashSet::new();
                visited.insert(lid);
                while let Some(parent_lid) = current.parent_lid {
                    if !visited.insert(parent_lid) {
                        break;
                    }
                    current = state.storage.get_key(&parent_lid).await.map_err(convert::error_to_status)?;
                    ancestors.push(proto::LineageEntry {
                        id: parent_lid.to_string(),
                        resource_type: "key".into(),
                        depth,
                        parent_id: current.parent_lid.map(|l| l.to_string()),
                    });
                    depth += 1;
                    if depth > 100 { break; }
                }
                Ok(Response::new(proto::GetKeyAncestorsResponse { ancestors }))
            },
        ).await
    }

    // ── Aliases ─────────────────────────────────────────────────────

    async fn create_alias(
        &self,
        request: Request<proto::CreateAliasRequest>,
    ) -> Result<Response<proto::CreateAliasResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let alias_name = req.alias_name.clone();
        ops::execute(
            &self.state,
            OpContext::alias(AuditAction::CreateAlias, principal, &alias_name),
            |state| async move {
                let lid = parse_lid(&req.target_key_id)?;
                let alias = keyrack_core::storage::AliasRecord {
                    alias_name: req.alias_name.clone(),
                    target_lid: lid,
                    created_at: chrono::Utc::now(),
                };
                state.storage.create_alias(&alias).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::CreateAliasResponse {
                    alias_name: req.alias_name,
                    target_key_id: lid.to_string(),
                }))
            },
        ).await
    }

    async fn delete_alias(
        &self,
        request: Request<proto::DeleteAliasRequest>,
    ) -> Result<Response<proto::DeleteAliasResponse>, Status> {
        let principal = self.principal(&request).await;
        let alias_name = request.into_inner().alias_name;
        ops::execute(
            &self.state,
            OpContext::alias(AuditAction::DeleteAlias, principal, &alias_name),
            |state| async move {
                state.storage.delete_alias(&alias_name).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::DeleteAliasResponse {}))
            },
        ).await
    }

    async fn list_aliases(
        &self,
        _request: Request<proto::ListAliasesRequest>,
    ) -> Result<Response<proto::ListAliasesResponse>, Status> {
        ops::execute(
            &self.state,
            OpContext::system(AuditAction::ListAliases, "", "Alias"),
            |state| async move {
                let aliases = state.storage.list_aliases().await.map_err(convert::error_to_status)?;
                let alias_list = aliases.iter().map(|a| proto::AliasEntry {
                    alias_name: a.alias_name.clone(),
                    target_key_id: a.target_lid.to_string(),
                    created_at: Some(convert::datetime_to_timestamp(&a.created_at)),
                }).collect();
                Ok(Response::new(proto::ListAliasesResponse { aliases: alias_list, next_cursor: String::new() }))
            },
        ).await
    }

    // ── Tags ────────────────────────────────────────────────────────

    async fn tag_resource(
        &self,
        request: Request<proto::TagResourceRequest>,
    ) -> Result<Response<proto::TagResourceResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::TagResource, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                for tag in &req.tags { record.user_tags.set(tag.key.clone(), tag.value.clone()); }
                record.occ_version += 1;
                record.updated_at = chrono::Utc::now();
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::TagResourceResponse {}))
            },
        ).await
    }

    async fn untag_resource(
        &self,
        request: Request<proto::UntagResourceRequest>,
    ) -> Result<Response<proto::UntagResourceResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::UntagResource, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let mut record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                for key in &req.tag_keys { record.user_tags.remove(key); }
                record.occ_version += 1;
                record.updated_at = chrono::Utc::now();
                state.storage.update_key(&record).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::UntagResourceResponse {}))
            },
        ).await
    }

    async fn list_resource_tags(
        &self,
        request: Request<proto::ListResourceTagsRequest>,
    ) -> Result<Response<proto::ListResourceTagsResponse>, Status> {
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        ops::execute(
            &self.state,
            OpContext::key(AuditAction::ListResourceTags, principal, &key_id),
            |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state.storage.get_key(&lid).await.map_err(convert::error_to_status)?;
                let tags = record.user_tags.iter().map(|(k, v)| proto::Tag { key: k.to_owned(), value: v.to_owned() }).collect();
                Ok(Response::new(proto::ListResourceTagsResponse { tags }))
            },
        ).await
    }

    // ── HSM connections ────────────────────────────────────────────

    async fn create_hsm_connection(
        &self,
        request: Request<proto::CreateHsmConnectionRequest>,
    ) -> Result<Response<proto::CreateHsmConnectionResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::CreateHsmConnection, principal, "", "HsmConnection"),
            |state| async move {
                let conn = keyrack_core::hsm::HsmConnection::new(
                    uuid::Uuid::new_v4().to_string(),
                    hsm_provider_from_proto(req.provider_type()),
                    &req.endpoint,
                    "",
                );
                state.storage.create_hsm_connection(&conn).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::CreateHsmConnectionResponse {
                    metadata: Some(hsm_connection_to_proto(&conn)),
                }))
            },
        ).await
    }

    async fn get_hsm_connection(
        &self,
        request: Request<proto::GetHsmConnectionRequest>,
    ) -> Result<Response<proto::GetHsmConnectionResponse>, Status> {
        let principal = self.principal(&request).await;
        let conn_id = request.into_inner().connection_id;
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::GetHsmConnection, principal, &conn_id, "HsmConnection"),
            |state| async move {
                let conn = state.storage.get_hsm_connection(&conn_id).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::GetHsmConnectionResponse {
                    metadata: Some(hsm_connection_to_proto(&conn)),
                }))
            },
        ).await
    }

    async fn list_hsm_connections(
        &self,
        request: Request<proto::ListHsmConnectionsRequest>,
    ) -> Result<Response<proto::ListHsmConnectionsResponse>, Status> {
        let principal = self.principal(&request).await;
        let _req = request.into_inner();
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::ListHsmConnections, principal, "*", "HsmConnection"),
            |state| async move {
                let conns = state.storage.list_hsm_connections().await.map_err(convert::error_to_status)?;
                let connections = conns.iter().map(hsm_connection_to_proto).collect();
                Ok(Response::new(proto::ListHsmConnectionsResponse {
                    connections,
                    next_cursor: String::new(),
                }))
            },
        ).await
    }

    async fn delete_hsm_connection(
        &self,
        request: Request<proto::DeleteHsmConnectionRequest>,
    ) -> Result<Response<proto::DeleteHsmConnectionResponse>, Status> {
        let principal = self.principal(&request).await;
        let conn_id = request.into_inner().connection_id;
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::DeleteHsmConnection, principal, &conn_id, "HsmConnection"),
            |state| async move {
                state.storage.delete_hsm_connection(&conn_id).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::DeleteHsmConnectionResponse {}))
            },
        ).await
    }

    async fn get_hsm_connection_status(
        &self,
        request: Request<proto::GetHsmConnectionStatusRequest>,
    ) -> Result<Response<proto::GetHsmConnectionStatusResponse>, Status> {
        let principal = self.principal(&request).await;
        let conn_id = request.into_inner().connection_id;
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::GetHsmConnectionStatus, principal, &conn_id, "HsmConnection"),
            |state| async move {
                let conn = state.storage.get_hsm_connection(&conn_id).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::GetHsmConnectionStatusResponse {
                    connection_id: conn.connection_id,
                    status: hsm_status_to_proto(conn.status).into(),
                    last_check: conn.last_health_check_at.map(|dt| convert::datetime_to_timestamp(&dt)),
                }))
            },
        ).await
    }

    // ── Namespaces ────────────────────────────────────────────────

    async fn register_namespace(
        &self,
        request: Request<proto::RegisterNamespaceRequest>,
    ) -> Result<Response<proto::RegisterNamespaceResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let name = req.name.clone();
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::RegisterNamespace, principal, &name, "Namespace"),
            |_state| async move {
                tracing::info!(name, "namespace registered (in-memory only)");
                Ok(Response::new(proto::RegisterNamespaceResponse { name }))
            },
        ).await
    }

    async fn list_namespaces(
        &self,
        request: Request<proto::ListNamespacesRequest>,
    ) -> Result<Response<proto::ListNamespacesResponse>, Status> {
        let principal = self.principal(&request).await;
        let _req = request.into_inner();
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::ListNamespaces, principal, "*", "Namespace"),
            |_state| async move {
                Ok(Response::new(proto::ListNamespacesResponse {
                    names: vec![],
                }))
            },
        ).await
    }

    async fn describe_namespace(
        &self,
        request: Request<proto::DescribeNamespaceRequest>,
    ) -> Result<Response<proto::DescribeNamespaceResponse>, Status> {
        let principal = self.principal(&request).await;
        let name = request.into_inner().name;
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::DescribeNamespace, principal, &name, "Namespace"),
            |_state| async move {
                Err(Status::not_found(format!("namespace '{name}' not found (namespace registry pending)")))
            },
        ).await
    }

    // ── Rotation jobs ─────────────────────────────────────────────

    #[allow(clippy::cast_possible_truncation)]
    async fn list_rotation_jobs(
        &self,
        request: Request<proto::ListRotationJobsRequest>,
    ) -> Result<Response<proto::ListRotationJobsResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::ListRotationJobs, principal, "*", "RotationJob"),
            |state| async move {
                let state_filter = req.state_filter.and_then(|s| {
                    proto::RotationJobState::try_from(s).ok()
                }).and_then(rotation_job_state_from_proto);
                let key_filter_lid = req.key_id.and_then(|k| parse_lid(&k).ok());
                let mut jobs = state.storage.list_rotation_jobs(state_filter).await
                    .map_err(convert::error_to_status)?;
                if let Some(lid) = &key_filter_lid {
                    jobs.retain(|j| j.parent_lid == *lid || j.dependent_lid == *lid);
                }
                let job_list = jobs.iter().map(rotation_job_to_proto).collect();
                Ok(Response::new(proto::ListRotationJobsResponse {
                    jobs: job_list,
                    next_cursor: String::new(),
                }))
            },
        ).await
    }

    async fn acknowledge_rotation_job(
        &self,
        request: Request<proto::AcknowledgeRotationJobRequest>,
    ) -> Result<Response<proto::AcknowledgeRotationJobResponse>, Status> {
        let principal = self.principal(&request).await;
        let job_id = request.into_inner().job_id;
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::AcknowledgeRotationJob, principal, &job_id, "RotationJob"),
            |state| async move {
                let mut job = state.storage.get_rotation_job(&job_id).await.map_err(convert::error_to_status)?;
                job.transition_to(keyrack_core::rotation::RotationJobState::Acknowledged)
                    .map_err(|(from, to)| Status::failed_precondition(format!("cannot transition from {from} to {to}")))?;
                state.storage.update_rotation_job(&job).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::AcknowledgeRotationJobResponse {
                    job: Some(rotation_job_to_proto(&job)),
                }))
            },
        ).await
    }

    async fn complete_rotation_job(
        &self,
        request: Request<proto::CompleteRotationJobRequest>,
    ) -> Result<Response<proto::CompleteRotationJobResponse>, Status> {
        let principal = self.principal(&request).await;
        let job_id = request.into_inner().job_id;
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::CompleteRotationJob, principal, &job_id, "RotationJob"),
            |state| async move {
                let mut job = state.storage.get_rotation_job(&job_id).await.map_err(convert::error_to_status)?;
                job.transition_to(keyrack_core::rotation::RotationJobState::Completed)
                    .map_err(|(from, to)| Status::failed_precondition(format!("cannot transition from {from} to {to}")))?;
                state.storage.update_rotation_job(&job).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::CompleteRotationJobResponse {
                    job: Some(rotation_job_to_proto(&job)),
                }))
            },
        ).await
    }

    async fn fail_rotation_job(
        &self,
        request: Request<proto::FailRotationJobRequest>,
    ) -> Result<Response<proto::FailRotationJobResponse>, Status> {
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let job_id = req.job_id.clone();
        ops::execute(
            &self.state,
            OpContext::resource(AuditAction::FailRotationJob, principal, &job_id, "RotationJob"),
            |state| async move {
                let mut job = state.storage.get_rotation_job(&req.job_id).await.map_err(convert::error_to_status)?;
                job.fail(&req.reason).map_err(|(from, to)| Status::failed_precondition(format!("cannot transition from {from} to {to}")))?;
                state.storage.update_rotation_job(&job).await.map_err(convert::error_to_status)?;
                Ok(Response::new(proto::FailRotationJobResponse {
                    job: Some(rotation_job_to_proto(&job)),
                }))
            },
        ).await
    }
}

#[cfg(feature = "crypto-endpoints")]
fn dek_length_from_spec(spec: i32) -> usize {
    match proto::KeySpec::try_from(spec) {
        Ok(proto::KeySpec::Rsa2048) => 256,
        Ok(proto::KeySpec::Rsa3072) => 384,
        Ok(proto::KeySpec::Rsa4096) => 512,
        _ => 32,
    }
}

// ── Conversion helpers ──────────────────────────────────────────────

#[allow(clippy::result_large_err)]
fn parse_lid(s: &str) -> Result<keyrack_core::lid::Lid, Status> {
    s.parse()
        .map_err(|_| Status::invalid_argument(format!("invalid key_id: {s}")))
}

fn hsm_provider_from_proto(pt: proto::HsmProviderType) -> keyrack_core::hsm::HsmProviderType {
    match pt {
        proto::HsmProviderType::Hsm => keyrack_core::hsm::HsmProviderType::Hsm,
        proto::HsmProviderType::Hyok => keyrack_core::hsm::HsmProviderType::Hyok,
        proto::HsmProviderType::Unspecified => keyrack_core::hsm::HsmProviderType::Hsm,
    }
}

fn hsm_status_to_proto(status: keyrack_core::hsm::HsmConnectionStatus) -> proto::HsmConnectionStatus {
    match status {
        keyrack_core::hsm::HsmConnectionStatus::Healthy => proto::HsmConnectionStatus::Healthy,
        keyrack_core::hsm::HsmConnectionStatus::Degraded => proto::HsmConnectionStatus::Degraded,
        keyrack_core::hsm::HsmConnectionStatus::Down => proto::HsmConnectionStatus::Down,
    }
}

fn hsm_provider_to_proto(pt: keyrack_core::hsm::HsmProviderType) -> proto::HsmProviderType {
    match pt {
        keyrack_core::hsm::HsmProviderType::Hsm => proto::HsmProviderType::Hsm,
        keyrack_core::hsm::HsmProviderType::Hyok => proto::HsmProviderType::Hyok,
    }
}

fn hsm_connection_to_proto(conn: &keyrack_core::hsm::HsmConnection) -> proto::HsmConnectionMetadata {
    proto::HsmConnectionMetadata {
        connection_id: conn.connection_id.clone(),
        provider_type: hsm_provider_to_proto(conn.provider_type).into(),
        endpoint: conn.endpoint.clone(),
        status: hsm_status_to_proto(conn.status).into(),
        created_at: Some(convert::datetime_to_timestamp(&conn.created_at)),
        last_health_check: conn.last_health_check_at.map(|dt| convert::datetime_to_timestamp(&dt)),
    }
}

fn rotation_job_state_to_proto(state: keyrack_core::rotation::RotationJobState) -> proto::RotationJobState {
    match state {
        keyrack_core::rotation::RotationJobState::Pending => proto::RotationJobState::Pending,
        keyrack_core::rotation::RotationJobState::Acknowledged => proto::RotationJobState::Acknowledged,
        keyrack_core::rotation::RotationJobState::Completed => proto::RotationJobState::Completed,
        keyrack_core::rotation::RotationJobState::Failed => proto::RotationJobState::Failed,
        keyrack_core::rotation::RotationJobState::Expired => proto::RotationJobState::Expired,
    }
}

fn rotation_job_state_from_proto(state: proto::RotationJobState) -> Option<keyrack_core::rotation::RotationJobState> {
    match state {
        proto::RotationJobState::Pending => Some(keyrack_core::rotation::RotationJobState::Pending),
        proto::RotationJobState::Acknowledged => Some(keyrack_core::rotation::RotationJobState::Acknowledged),
        proto::RotationJobState::Completed => Some(keyrack_core::rotation::RotationJobState::Completed),
        proto::RotationJobState::Failed => Some(keyrack_core::rotation::RotationJobState::Failed),
        proto::RotationJobState::Expired => Some(keyrack_core::rotation::RotationJobState::Expired),
        proto::RotationJobState::Unspecified => None,
    }
}

#[allow(clippy::cast_possible_truncation)]
fn rotation_job_to_proto(job: &keyrack_core::rotation::RotationJob) -> proto::RotationJobMetadata {
    proto::RotationJobMetadata {
        job_id: job.job_id.clone(),
        key_id: job.parent_lid.to_string(),
        from_version: (job.new_version.saturating_sub(1)) as u32,
        to_version: job.new_version as u32,
        state: rotation_job_state_to_proto(job.state).into(),
        created_at: Some(convert::datetime_to_timestamp(&job.created_at)),
        expires_at: Some(convert::datetime_to_timestamp(&job.expires_at)),
        failure_reason: job.failure_reason.clone(),
    }
}
