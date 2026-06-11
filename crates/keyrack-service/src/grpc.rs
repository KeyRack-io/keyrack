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

    fn request_id<T>(request: &Request<T>) -> String {
        ops::extract_request_id_grpc(request)
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
        {
            let _ = request;
            return Err(crypto_disabled("Encrypt"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let key_id = req.key_id.clone();

            let ec_hash = if req.encryption_context.is_empty() {
                None
            } else {
                let ec = build_encryption_context(&req.encryption_context);
                ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::hash)
            };

            let mut op_ctx = OpContext::key(AuditAction::Encrypt, principal, &key_id);
            op_ctx.encryption_context_hash = ec_hash;
            op_ctx.request_id = request_id;

            ops::execute(&self.state, op_ctx, |state| async move {
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

                let ec_aad = ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let ec_hash = ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );

                let header = keyrack_core::header::CiphertextHeader::new(
                    record.lid,
                    record.current_key_version,
                    ec_hash,
                );

                let aad = header.build_aad(&ec_aad);

                let enc_entry = state
                    .providers
                    .resolve_for_primary(&record)
                    .map_err(convert::error_to_status)?;
                let output = enc_entry
                    .provider
                    .encrypt(&primary_version.key_handle, &req.plaintext, &aad)
                    .await
                    .map_err(convert::error_to_status)?;

                let ciphertext_blob = header.wrap_payload(&output.ciphertext);

                #[allow(clippy::cast_possible_truncation)]
                Ok(Response::new(proto::EncryptResponse {
                    ciphertext_blob,
                    key_id: record.lid.to_string(),
                    key_version: record.current_key_version as u32,
                }))
            })
            .await
        }
    }

    async fn decrypt(
        &self,
        request: Request<proto::DecryptRequest>,
    ) -> Result<Response<proto::DecryptResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("Decrypt"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let key_id = req.key_id.clone();

            let ec_hash = if req.encryption_context.is_empty() {
                None
            } else {
                let ec = build_encryption_context(&req.encryption_context);
                ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::hash)
            };

            let mut op_ctx = OpContext::key(AuditAction::Decrypt, principal, &key_id);
            op_ctx.encryption_context_hash = ec_hash;
            op_ctx.request_id = request_id;

            ops::execute(&self.state, op_ctx, |state| async move {
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

                let version_record = record
                    .key_versions
                    .iter()
                    .find(|v| v.version_number == header.key_version)
                    .ok_or_else(|| Status::not_found("key version not found"))?;

                let dec_entry = state
                    .providers
                    .resolve_for_version(&record, header.key_version)
                    .map_err(convert::error_to_status)?;

                let ec_aad = ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let aad = header.build_aad(&ec_aad);

                let plaintext = dec_entry
                    .provider
                    .decrypt(&version_record.key_handle, ciphertext, &aad)
                    .await
                    .map_err(convert::error_to_status)?;

                Ok(Response::new(proto::DecryptResponse {
                    plaintext: plaintext.expose().clone(),
                    key_id: record.lid.to_string(),
                }))
            })
            .await
        }
    }

    async fn re_encrypt(
        &self,
        request: Request<proto::ReEncryptRequest>,
    ) -> Result<Response<proto::ReEncryptResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("ReEncrypt"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let src_key_id = req.source_key_id.clone();

            let dst_ec_hash = if req.destination_encryption_context.is_empty() {
                None
            } else {
                let ec = build_encryption_context(&req.destination_encryption_context);
                ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::hash)
            };

            let mut op_ctx = OpContext::key(AuditAction::ReEncrypt, principal, &src_key_id);
            op_ctx.encryption_context_hash = dst_ec_hash;
            op_ctx.request_id = request_id;

            ops::execute(&self.state, op_ctx, |state| async move {
                let src_lid = parse_lid(&req.source_key_id)?;
                let dst_lid = parse_lid(&req.destination_key_id)?;

                let src_record = state
                    .storage
                    .get_key(&src_lid)
                    .await
                    .map_err(convert::error_to_status)?;
                let dst_record = state
                    .storage
                    .get_key(&dst_lid)
                    .await
                    .map_err(convert::error_to_status)?;

                let src_ec = build_encryption_context(&req.source_encryption_context);
                let dst_ec = build_encryption_context(&req.destination_encryption_context);

                let (header, ciphertext) =
                    keyrack_core::header::CiphertextHeader::unwrap_payload(&req.ciphertext_blob)
                        .map_err(|e| Status::invalid_argument(e.to_string()))?;

                let src_version = src_record
                    .key_versions
                    .iter()
                    .find(|v| v.version_number == header.key_version)
                    .ok_or_else(|| Status::not_found("source key version not found"))?;

                let src_ec_aad = src_ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();
                let src_aad = header.build_aad(&src_ec_aad);

                let src_re_entry = state
                    .providers
                    .resolve_for_version(&src_record, header.key_version)
                    .map_err(convert::error_to_status)?;
                let dst_re_entry = state
                    .providers
                    .resolve_for_primary(&dst_record)
                    .map_err(convert::error_to_status)?;

                let dst_primary = dst_record
                    .key_versions
                    .iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("destination has no primary version"))?;

                let dst_ec_hash = dst_ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );

                let new_header = keyrack_core::header::CiphertextHeader::new(
                    dst_record.lid,
                    dst_record.current_key_version,
                    dst_ec_hash,
                );

                let dst_ec_aad = dst_ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();
                let dst_aad = new_header.build_aad(&dst_ec_aad);

                let output =
                    if std::sync::Arc::ptr_eq(&src_re_entry.provider, &dst_re_entry.provider) {
                        src_re_entry
                            .provider
                            .re_encrypt(
                                &src_version.key_handle,
                                ciphertext,
                                &src_aad,
                                &dst_primary.key_handle,
                                &dst_aad,
                            )
                            .await
                            .map_err(convert::error_to_status)?
                    } else {
                        let plaintext = src_re_entry
                            .provider
                            .decrypt(&src_version.key_handle, ciphertext, &src_aad)
                            .await
                            .map_err(convert::error_to_status)?;
                        dst_re_entry
                            .provider
                            .encrypt(&dst_primary.key_handle, plaintext.expose(), &dst_aad)
                            .await
                            .map_err(convert::error_to_status)?
                    };

                Ok(Response::new(proto::ReEncryptResponse {
                    ciphertext_blob: new_header.wrap_payload(&output.ciphertext),
                    source_key_id: src_record.lid.to_string(),
                    destination_key_id: dst_record.lid.to_string(),
                }))
            })
            .await
        }
    }

    async fn generate_data_key(
        &self,
        request: Request<proto::GenerateDataKeyRequest>,
    ) -> Result<Response<proto::GenerateDataKeyResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("GenerateDataKey"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let key_id = req.key_id.clone();

            let ec_hash = if req.encryption_context.is_empty() {
                None
            } else {
                let ec = build_encryption_context(&req.encryption_context);
                ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::hash)
            };

            let mut op_ctx = OpContext::key(AuditAction::GenerateDataKey, principal, &key_id);
            op_ctx.encryption_context_hash = ec_hash;
            op_ctx.request_id = request_id;

            ops::execute(&self.state, op_ctx, |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state
                    .storage
                    .get_key(&lid)
                    .await
                    .map_err(convert::error_to_status)?;

                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition("key not in Enabled state"));
                }

                let primary = record
                    .key_versions
                    .iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;

                let ec = build_encryption_context(&req.encryption_context);
                let ec_aad = ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();

                let ec_hash = ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );

                let header = keyrack_core::header::CiphertextHeader::new(
                    record.lid,
                    record.current_key_version,
                    ec_hash,
                );

                let aad = header.build_aad(&ec_aad);
                let dek_len = dek_length_from_spec(req.key_spec);

                let gdek_entry = state
                    .providers
                    .resolve_for_primary(&record)
                    .map_err(convert::error_to_status)?;
                let output = gdek_entry
                    .provider
                    .generate_data_key(&primary.key_handle, dek_len, &aad)
                    .await
                    .map_err(convert::error_to_status)?;

                Ok(Response::new(proto::GenerateDataKeyResponse {
                    plaintext_data_key: output.plaintext_key.into_inner(),
                    encrypted_data_key: header.wrap_payload(&output.encrypted_key),
                    key_id: record.lid.to_string(),
                }))
            })
            .await
        }
    }

    async fn generate_data_key_without_plaintext(
        &self,
        request: Request<proto::GenerateDataKeyWithoutPlaintextRequest>,
    ) -> Result<Response<proto::GenerateDataKeyWithoutPlaintextResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("GenerateDataKeyWithoutPlaintext"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let key_id = req.key_id.clone();

            let ec_hash = if req.encryption_context.is_empty() {
                None
            } else {
                let ec = build_encryption_context(&req.encryption_context);
                ec.as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::hash)
            };

            let mut op_ctx = OpContext::key(
                AuditAction::GenerateDataKeyWithoutPlaintext,
                principal,
                &key_id,
            );
            op_ctx.encryption_context_hash = ec_hash;
            op_ctx.request_id = request_id;

            ops::execute(&self.state, op_ctx, |state| async move {
                let lid = parse_lid(&key_id)?;
                let record = state
                    .storage
                    .get_key(&lid)
                    .await
                    .map_err(convert::error_to_status)?;
                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition("key not in Enabled state"));
                }
                let primary = record
                    .key_versions
                    .iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;
                let ec = build_encryption_context(&req.encryption_context);
                let ec_aad = ec
                    .as_ref()
                    .map(keyrack_core::encryption_context::EncryptionContext::to_aad_bytes)
                    .unwrap_or_default();
                let ec_hash = ec.as_ref().map_or(
                    [0u8; 32],
                    keyrack_core::encryption_context::EncryptionContext::hash,
                );
                let header = keyrack_core::header::CiphertextHeader::new(
                    record.lid,
                    record.current_key_version,
                    ec_hash,
                );
                let aad = header.build_aad(&ec_aad);
                let dek_len = dek_length_from_spec(req.key_spec);
                let gdkwp_entry = state
                    .providers
                    .resolve_for_primary(&record)
                    .map_err(convert::error_to_status)?;
                let output = gdkwp_entry
                    .provider
                    .generate_data_key(&primary.key_handle, dek_len, &aad)
                    .await
                    .map_err(convert::error_to_status)?;
                Ok(Response::new(
                    proto::GenerateDataKeyWithoutPlaintextResponse {
                        encrypted_data_key: header.wrap_payload(&output.encrypted_key),
                        key_id: record.lid.to_string(),
                    },
                ))
            })
            .await
        }
    }

    async fn generate_random(
        &self,
        request: Request<proto::GenerateRandomRequest>,
    ) -> Result<Response<proto::GenerateRandomResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("GenerateRandom"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let req = request.into_inner();

            let mut op_ctx = OpContext::system(AuditAction::GenerateRandom, "", "System");
            op_ctx.request_id = request_id;
            ops::execute(&self.state, op_ctx, |state| async move {
                let random_bytes = state
                    .providers
                    .default_entry()
                    .provider
                    .generate_random(req.number_of_bytes as usize)
                    .await
                    .map_err(convert::error_to_status)?;
                Ok(Response::new(proto::GenerateRandomResponse {
                    random_bytes: random_bytes.into_inner(),
                }))
            })
            .await
        }
    }

    async fn sign(
        &self,
        request: Request<proto::SignRequest>,
    ) -> Result<Response<proto::SignResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("Sign"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let key_id = req.key_id.clone();

            let mut op_ctx = OpContext::key(AuditAction::Sign, principal, &key_id);
            op_ctx.request_id = request_id;
            ops::execute(&self.state, op_ctx, |state| async move {
                let alg_proto = proto::SigningAlgorithm::try_from(req.signing_algorithm)
                    .unwrap_or(proto::SigningAlgorithm::Unspecified);
                let alg = convert::proto_to_signing_algorithm(alg_proto)
                    .ok_or_else(|| Status::invalid_argument("signing algorithm required"))?;

                let lid = parse_lid(&key_id)?;
                let record = state
                    .storage
                    .get_key(&lid)
                    .await
                    .map_err(convert::error_to_status)?;
                if !record.state.permits_encrypt() {
                    return Err(Status::failed_precondition(
                        "sign not permitted in current state",
                    ));
                }
                let primary_version = record
                    .key_versions
                    .iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;
                let sign_entry = state
                    .providers
                    .resolve_for_primary(&record)
                    .map_err(convert::error_to_status)?;
                let signature = sign_entry
                    .provider
                    .sign(&primary_version.key_handle, alg, &req.message)
                    .await
                    .map_err(convert::error_to_status)?;
                Ok(Response::new(proto::SignResponse {
                    signature,
                    key_id: record.lid.to_string(),
                    signing_algorithm: convert::signing_algorithm_to_proto(&alg).into(),
                }))
            })
            .await
        }
    }

    async fn verify(
        &self,
        request: Request<proto::VerifyRequest>,
    ) -> Result<Response<proto::VerifyResponse>, Status> {
        #[cfg(not(feature = "crypto-endpoints"))]
        {
            let _ = request;
            return Err(crypto_disabled("Verify"));
        }

        #[cfg(feature = "crypto-endpoints")]
        {
            let request_id = Self::request_id(&request);
            let principal = self.principal(&request).await;
            let req = request.into_inner();
            let key_id = req.key_id.clone();

            let mut op_ctx = OpContext::key(AuditAction::Verify, principal, &key_id);
            op_ctx.request_id = request_id;
            ops::execute(&self.state, op_ctx, |state| async move {
                let alg_proto = proto::SigningAlgorithm::try_from(req.signing_algorithm)
                    .unwrap_or(proto::SigningAlgorithm::Unspecified);
                let alg = convert::proto_to_signing_algorithm(alg_proto)
                    .ok_or_else(|| Status::invalid_argument("signing algorithm required"))?;
                let lid = parse_lid(&key_id)?;
                let record = state
                    .storage
                    .get_key(&lid)
                    .await
                    .map_err(convert::error_to_status)?;
                if !record.state.permits_decrypt() {
                    return Err(Status::failed_precondition(
                        "verify not permitted in current state",
                    ));
                }
                let primary_version = record
                    .key_versions
                    .iter()
                    .find(|v| v.is_primary)
                    .ok_or_else(|| Status::internal("no primary key version"))?;
                let verify_entry = state
                    .providers
                    .resolve_for_primary(&record)
                    .map_err(convert::error_to_status)?;
                let valid = verify_entry
                    .provider
                    .verify(
                        &primary_version.key_handle,
                        alg,
                        &req.message,
                        &req.signature,
                    )
                    .await
                    .map_err(convert::error_to_status)?;
                Ok(Response::new(proto::VerifyResponse {
                    signature_valid: valid,
                    key_id: record.lid.to_string(),
                    signing_algorithm: convert::signing_algorithm_to_proto(&alg).into(),
                }))
            })
            .await
        }
    }

    // ── Key lifecycle ───────────────────────────────────────────────

    async fn create_key(
        &self,
        request: Request<proto::CreateKeyRequest>,
    ) -> Result<Response<proto::CreateKeyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();

        let mut op_ctx = OpContext::key(AuditAction::CreateKey, principal, "(new)");
        op_ctx.request_id = request_id;
        ops::execute(
            &self.state,
            op_ctx,
            |state| async move {
                let spec = convert::proto_to_key_spec(
                    proto::KeySpec::try_from(req.key_spec).unwrap_or(proto::KeySpec::Unspecified),
                )
                .ok_or_else(|| Status::invalid_argument("key_spec is required"))?;

                if matches!(&spec, keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 } | keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 2048 }) {
                    tracing::warn!(
                        "RSA-2048 provides only 112-bit security and is deprecated per NIST guidance (2030 deadline). \
                         Consider RSA-3072+ or ECDSA P-256 for new keys."
                    );
                }

                let mut caller_attrs: std::collections::BTreeMap<String, String> =
                    req.attributes.clone().into_iter().collect();
                let namespace = req.namespace.clone();
                let requested_provider = caller_attrs.remove("keyrack.provider");
                if !namespace.is_empty() {
                    caller_attrs.insert("namespace".to_string(), namespace);
                }
                let (lid, attrs) = crate::domain::generate_key_lid_from_attrs(caller_attrs);
                let identity_tags = keyrack_core::tags::IdentityTags::from_attribute_set(&attrs);

                // Route new key to the appropriate provider.
                let provider_name = state.provider_router.select(&identity_tags);
                if let Some(req_provider) = &requested_provider {
                    if req_provider != provider_name.as_str() {
                        return Err(Status::failed_precondition(format!(
                            "requested provider '{req_provider}' but routing policy selected '{}'",
                            provider_name.as_str()
                        )));
                    }
                }
                let entry = state.providers.resolve(&provider_name).map_err(convert::error_to_status)?;

                let handle = entry.provider.generate_key(&spec).await.map_err(convert::error_to_status)?;

                let parent_lid = req.parent_key_id
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(parse_lid)
                    .transpose()?;

                let now = chrono::Utc::now();
                let key_usage = match spec {
                    keyrack_core::key::KeySpec::Aes256 => keyrack_core::key::KeyUsage::EncryptDecrypt,
                    _ => keyrack_core::key::KeyUsage::SignVerify,
                };

                let record = keyrack_core::key::KeyRecord {
                    lid,
                    canonicalization_version: keyrack_core::canon::CanonicalizationVersion::V1,
                    parent_lid,
                    occ_version: 1,
                    current_key_version: 1,
                    state: keyrack_core::key::KeyState::Enabled,
                    key_usage,
                    key_spec: spec,
                    origin: keyrack_core::key::KeyOrigin::KeyRack,
                    provider_class: entry.class,
                    provider_ref: Some(provider_name.clone()),
                    identity_tags,
                    user_tags: keyrack_core::tags::UserTags::new(),
                    created_at: now,
                    updated_at: now,
                    scheduled_deletion_at: None,
                    description: req.description,
                    key_versions: vec![keyrack_core::key::KeyVersionRecord {
                        version_number: 1,
                        key_handle: handle,
                        provider_ref: Some(provider_name.clone()),
                        created_at: now,
                        is_primary: true,
                    }],
                };

                state.storage.create_key(&record).await.map_err(convert::error_to_status)?;

                if let Some(nats) = &state.nats_publisher {
                    if let Err(e) = nats.publish_key_created(&lid).await {
                        tracing::warn!(lid = %lid, error = %e, "NATS key-created publish failed");
                    }
                }

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
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::GetKey, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::GetKeyResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn describe_key(
        &self,
        request: Request<proto::DescribeKeyRequest>,
    ) -> Result<Response<proto::DescribeKeyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::DescribeKey, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::DescribeKeyResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn update_key(
        &self,
        request: Request<proto::UpdateKeyRequest>,
    ) -> Result<Response<proto::UpdateKeyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::UpdateKey, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            record.description = req.description.unwrap_or_default();
            record.occ_version += 1;
            record.updated_at = chrono::Utc::now();
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::UpdateKeyResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn list_keys(
        &self,
        request: Request<proto::ListKeysRequest>,
    ) -> Result<Response<proto::ListKeysResponse>, Status> {
        let request_id = Self::request_id(&request);
        let mut op_ctx = OpContext::system(AuditAction::ListKeys, "", "Key");
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let req = request.into_inner();
            let limit = if req.max_results == 0 {
                100
            } else {
                req.max_results
            };
            let filter = keyrack_core::storage::KeyFilter {
                user_tags: vec![],
                state: None,
                limit: Some(limit),
                cursor: if req.cursor.is_empty() {
                    None
                } else {
                    Some(req.cursor)
                },
            };
            let page = state
                .storage
                .list_keys(&filter)
                .await
                .map_err(convert::error_to_status)?;
            let keys = page
                .items
                .iter()
                .map(convert::key_record_to_metadata)
                .collect();
            Ok(Response::new(proto::ListKeysResponse {
                keys,
                next_cursor: page.next_cursor.unwrap_or_default(),
            }))
        })
        .await
    }

    async fn enable_key(
        &self,
        request: Request<proto::EnableKeyRequest>,
    ) -> Result<Response<proto::EnableKeyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::EnableKey, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let old_state = record.state.to_string();
            record
                .transition_to(keyrack_core::key::KeyState::Enabled)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            if let Some(nats) = &state.nats_publisher {
                if let Err(e) = nats
                    .publish_state_changed(&lid, &old_state, "enabled")
                    .await
                {
                    tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
                }
            }
            Ok(Response::new(proto::EnableKeyResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn disable_key(
        &self,
        request: Request<proto::DisableKeyRequest>,
    ) -> Result<Response<proto::DisableKeyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::DisableKey, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let old_state = record.state.to_string();
            record
                .transition_to(keyrack_core::key::KeyState::Disabled)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            if let Some(nats) = &state.nats_publisher {
                if let Err(e) = nats
                    .publish_state_changed(&lid, &old_state, "disabled")
                    .await
                {
                    tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
                }
            }

            // Cascade: disable all descendant keys recursively
            let cascade_start = std::time::Instant::now();
            let mut cascade_count = 0u64;
            let mut queue = vec![lid];
            while let Some(parent) = queue.pop() {
                let children = state
                    .storage
                    .list_children(&parent)
                    .await
                    .map_err(convert::error_to_status)?;
                for mut child in children {
                    if child.state == keyrack_core::key::KeyState::Enabled
                        && child
                            .transition_to(keyrack_core::key::KeyState::Disabled)
                            .is_ok()
                    {
                        if let Err(e) = state.storage.update_key(&child).await {
                            tracing::error!(
                                child_lid = %child.lid,
                                error = %e,
                                "failed to disable descendant key during cascade"
                            );
                            return Err(Status::internal(format!(
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
                // Emit NATS invalidation if event sink is configured
                state
                    .emit_audit_event(&key_id, &format!("disabled {cascade_count} descendant(s)"))
                    .await;
            }

            Ok(Response::new(proto::DisableKeyResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn schedule_key_deletion(
        &self,
        request: Request<proto::ScheduleKeyDeletionRequest>,
    ) -> Result<Response<proto::ScheduleKeyDeletionResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::ScheduleKeyDeletion, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let days = if req.grace_period_days == 0 {
                7
            } else {
                req.grace_period_days
            };
            record
                .transition_to(keyrack_core::key::KeyState::PendingDeletion)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            record.scheduled_deletion_at =
                Some(chrono::Utc::now() + chrono::Duration::days(i64::from(days)));
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::ScheduleKeyDeletionResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
                deletion_date: record
                    .scheduled_deletion_at
                    .as_ref()
                    .map(convert::datetime_to_timestamp),
            }))
        })
        .await
    }

    async fn cancel_key_deletion(
        &self,
        request: Request<proto::CancelKeyDeletionRequest>,
    ) -> Result<Response<proto::CancelKeyDeletionResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::CancelKeyDeletion, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            if record.state != keyrack_core::key::KeyState::PendingDeletion {
                return Err(Status::failed_precondition(
                    "can only cancel deletion from PendingDeletion",
                ));
            }
            record
                .transition_to(keyrack_core::key::KeyState::Disabled)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            record.scheduled_deletion_at = None;
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::CancelKeyDeletionResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn report_key_compromise(
        &self,
        request: Request<proto::ReportKeyCompromiseRequest>,
    ) -> Result<Response<proto::ReportKeyCompromiseResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::ReportKeyCompromise, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let old_state = record.state.to_string();
            record
                .transition_to(keyrack_core::key::KeyState::Compromised)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            if let Some(nats) = &state.nats_publisher {
                if let Err(e) = nats
                    .publish_state_changed(&lid, &old_state, "compromised")
                    .await
                {
                    tracing::warn!(lid = %lid, error = %e, "NATS state-changed publish failed");
                }
            }
            Ok(Response::new(proto::ReportKeyCompromiseResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
            }))
        })
        .await
    }

    async fn rotate_key(
        &self,
        request: Request<proto::RotateKeyRequest>,
    ) -> Result<Response<proto::RotateKeyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::RotateKey, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            if record.state != keyrack_core::key::KeyState::Enabled {
                return Err(Status::failed_precondition("key must be Enabled to rotate"));
            }
            let rot_entry = state
                .providers
                .resolve_for_primary(&record)
                .map_err(convert::error_to_status)?;
            let new_handle = rot_entry
                .provider
                .generate_key(&record.key_spec)
                .await
                .map_err(convert::error_to_status)?;
            let new_version_provider_ref = record.provider_ref.clone();
            let new_version = record.current_key_version + 1;
            for v in &mut record.key_versions {
                v.is_primary = false;
            }
            record
                .key_versions
                .push(keyrack_core::key::KeyVersionRecord {
                    version_number: new_version,
                    key_handle: new_handle,
                    provider_ref: new_version_provider_ref,
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
                .map_err(convert::error_to_status)?;

            // Create rotation jobs for all descendant keys recursively (§5.6)
            let mut queue = vec![lid];
            let mut visited = std::collections::HashSet::new();
            visited.insert(lid);
            let mut total_jobs = 0usize;
            while let Some(parent_lid) = queue.pop() {
                let children = state
                    .storage
                    .list_children(&parent_lid)
                    .await
                    .map_err(convert::error_to_status)?;
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

            #[allow(clippy::cast_possible_truncation)]
            Ok(Response::new(proto::RotateKeyResponse {
                metadata: Some(convert::key_record_to_metadata(&record)),
                new_version: new_version as u32,
            }))
        })
        .await
    }

    // ── Key versions ────────────────────────────────────────────────

    async fn list_key_versions(
        &self,
        request: Request<proto::ListKeyVersionsRequest>,
    ) -> Result<Response<proto::ListKeyVersionsResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::ListKeyVersions, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let versions: Vec<_> = record
                .key_versions
                .iter()
                .map(convert::key_version_to_proto)
                .collect();
            Ok(Response::new(proto::ListKeyVersionsResponse {
                versions,
                next_cursor: String::new(),
            }))
        })
        .await
    }

    async fn get_key_version(
        &self,
        request: Request<proto::GetKeyVersionRequest>,
    ) -> Result<Response<proto::GetKeyVersionResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::GetKeyVersion, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let version = record
                .key_versions
                .iter()
                .find(|v| v.version_number == u64::from(req.version))
                .ok_or_else(|| Status::not_found(format!("version {} not found", req.version)))?;
            Ok(Response::new(proto::GetKeyVersionResponse {
                version: Some(convert::key_version_to_proto(version)),
            }))
        })
        .await
    }

    // ── Rotation control ────────────────────────────────────────────
    // Rotation policy is persisted via user_tags on the KeyRecord:
    //   _keyrack_rotation_enabled      = "true" | "false"
    //   _keyrack_rotation_interval_days = "<u32>"

    async fn enable_key_rotation(
        &self,
        request: Request<proto::EnableKeyRotationRequest>,
    ) -> Result<Response<proto::EnableKeyRotationResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::EnableKeyRotation, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            record.user_tags.set("_keyrack_rotation_enabled", "true");
            record.occ_version += 1;
            record.updated_at = chrono::Utc::now();
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            tracing::info!(key_id, "rotation enabled");
            Ok(Response::new(proto::EnableKeyRotationResponse {}))
        })
        .await
    }

    async fn disable_key_rotation(
        &self,
        request: Request<proto::DisableKeyRotationRequest>,
    ) -> Result<Response<proto::DisableKeyRotationResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::DisableKeyRotation, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            record.user_tags.set("_keyrack_rotation_enabled", "false");
            record.occ_version += 1;
            record.updated_at = chrono::Utc::now();
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            tracing::info!(key_id, "rotation disabled");
            Ok(Response::new(proto::DisableKeyRotationResponse {}))
        })
        .await
    }

    async fn get_key_rotation_status(
        &self,
        request: Request<proto::GetKeyRotationStatusRequest>,
    ) -> Result<Response<proto::GetKeyRotationStatusResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::GetKeyRotationStatus, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let rotation_enabled =
                record.user_tags.get("_keyrack_rotation_enabled") == Some("true");
            let last_rotated = record
                .key_versions
                .iter()
                .filter(|v| !v.is_primary)
                .max_by_key(|v| v.version_number)
                .map(|v| convert::datetime_to_timestamp(&v.created_at));
            Ok(Response::new(proto::GetKeyRotationStatusResponse {
                rotation_enabled,
                next_rotation_date: None,
                last_rotated_at: last_rotated,
            }))
        })
        .await
    }

    #[allow(clippy::cast_possible_truncation)]
    async fn get_key_rotation_history(
        &self,
        request: Request<proto::GetKeyRotationHistoryRequest>,
    ) -> Result<Response<proto::GetKeyRotationHistoryResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::GetKeyRotationHistory, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
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
        })
        .await
    }

    async fn get_key_rotation_policy(
        &self,
        request: Request<proto::GetKeyRotationPolicyRequest>,
    ) -> Result<Response<proto::GetKeyRotationPolicyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::GetKeyRotationPolicy, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let enabled = record.user_tags.get("_keyrack_rotation_enabled") == Some("true");
            let rotation_interval_days = record
                .user_tags
                .get("_keyrack_rotation_interval_days")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            Ok(Response::new(proto::GetKeyRotationPolicyResponse {
                policy: Some(proto::RotationPolicy {
                    enabled,
                    rotation_interval_days,
                }),
            }))
        })
        .await
    }

    async fn set_key_rotation_policy(
        &self,
        request: Request<proto::SetKeyRotationPolicyRequest>,
    ) -> Result<Response<proto::SetKeyRotationPolicyResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::SetKeyRotationPolicy, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            if let Some(policy) = &req.policy {
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
                    .map_err(convert::error_to_status)?;
                tracing::info!(
                    key_id,
                    enabled = policy.enabled,
                    interval_days = policy.rotation_interval_days,
                    "rotation policy persisted"
                );
            }
            Ok(Response::new(proto::SetKeyRotationPolicyResponse {}))
        })
        .await
    }

    // ── Hierarchy queries ───────────────────────────────────────────

    async fn get_key_dependents(
        &self,
        request: Request<proto::GetKeyDependentsRequest>,
    ) -> Result<Response<proto::GetKeyDependentsResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::GetKeyDependents, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut dependents = Vec::new();
            let mut queue = vec![(lid, 1u32)];
            let mut visited = std::collections::HashSet::new();
            visited.insert(lid);
            while let Some((parent_lid, depth)) = queue.pop() {
                let children = state
                    .storage
                    .list_children(&parent_lid)
                    .await
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
            Ok(Response::new(proto::GetKeyDependentsResponse {
                dependents,
            }))
        })
        .await
    }

    async fn get_key_ancestors(
        &self,
        request: Request<proto::GetKeyAncestorsRequest>,
    ) -> Result<Response<proto::GetKeyAncestorsResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::GetKeyAncestors, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut ancestors = Vec::new();
            let mut current = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let mut depth = 1u32;
            let mut visited = std::collections::HashSet::new();
            visited.insert(lid);
            while let Some(parent_lid) = current.parent_lid {
                if !visited.insert(parent_lid) {
                    break;
                }
                current = state
                    .storage
                    .get_key(&parent_lid)
                    .await
                    .map_err(convert::error_to_status)?;
                ancestors.push(proto::LineageEntry {
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
            Ok(Response::new(proto::GetKeyAncestorsResponse { ancestors }))
        })
        .await
    }

    // ── Aliases ─────────────────────────────────────────────────────

    async fn create_alias(
        &self,
        request: Request<proto::CreateAliasRequest>,
    ) -> Result<Response<proto::CreateAliasResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let alias_name = req.alias_name.clone();
        let mut op_ctx = OpContext::alias(AuditAction::CreateAlias, principal, &alias_name);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&req.target_key_id)?;
            let alias = keyrack_core::storage::AliasRecord {
                alias_name: req.alias_name.clone(),
                target_lid: lid,
                created_at: chrono::Utc::now(),
            };
            state
                .storage
                .create_alias(&alias)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::CreateAliasResponse {
                alias_name: req.alias_name,
                target_key_id: lid.to_string(),
            }))
        })
        .await
    }

    async fn delete_alias(
        &self,
        request: Request<proto::DeleteAliasRequest>,
    ) -> Result<Response<proto::DeleteAliasResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let alias_name = request.into_inner().alias_name;
        let mut op_ctx = OpContext::alias(AuditAction::DeleteAlias, principal, &alias_name);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            state
                .storage
                .delete_alias(&alias_name)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::DeleteAliasResponse {}))
        })
        .await
    }

    async fn list_aliases(
        &self,
        _request: Request<proto::ListAliasesRequest>,
    ) -> Result<Response<proto::ListAliasesResponse>, Status> {
        let mut op_ctx = OpContext::system(AuditAction::ListAliases, "", "Alias");
        op_ctx.request_id = ops::extract_request_id_grpc(&_request);
        ops::execute(&self.state, op_ctx, |state| async move {
            let aliases = state
                .storage
                .list_aliases()
                .await
                .map_err(convert::error_to_status)?;
            let alias_list = aliases
                .iter()
                .map(|a| proto::AliasEntry {
                    alias_name: a.alias_name.clone(),
                    target_key_id: a.target_lid.to_string(),
                    created_at: Some(convert::datetime_to_timestamp(&a.created_at)),
                })
                .collect();
            Ok(Response::new(proto::ListAliasesResponse {
                aliases: alias_list,
                next_cursor: String::new(),
            }))
        })
        .await
    }

    // ── Tags ────────────────────────────────────────────────────────

    async fn tag_resource(
        &self,
        request: Request<proto::TagResourceRequest>,
    ) -> Result<Response<proto::TagResourceResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::TagResource, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            for tag in &req.tags {
                record.user_tags.set(tag.key.clone(), tag.value.clone());
            }
            record.occ_version += 1;
            record.updated_at = chrono::Utc::now();
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::TagResourceResponse {}))
        })
        .await
    }

    async fn untag_resource(
        &self,
        request: Request<proto::UntagResourceRequest>,
    ) -> Result<Response<proto::UntagResourceResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let key_id = req.key_id.clone();
        let mut op_ctx = OpContext::key(AuditAction::UntagResource, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let mut record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            for key in &req.tag_keys {
                record.user_tags.remove(key);
            }
            record.occ_version += 1;
            record.updated_at = chrono::Utc::now();
            state
                .storage
                .update_key(&record)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::UntagResourceResponse {}))
        })
        .await
    }

    async fn list_resource_tags(
        &self,
        request: Request<proto::ListResourceTagsRequest>,
    ) -> Result<Response<proto::ListResourceTagsResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let key_id = request.into_inner().key_id;
        let mut op_ctx = OpContext::key(AuditAction::ListResourceTags, principal, &key_id);
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let lid = parse_lid(&key_id)?;
            let record = state
                .storage
                .get_key(&lid)
                .await
                .map_err(convert::error_to_status)?;
            let tags = record
                .user_tags
                .iter()
                .map(|(k, v)| proto::Tag {
                    key: k.to_owned(),
                    value: v.to_owned(),
                })
                .collect();
            Ok(Response::new(proto::ListResourceTagsResponse { tags }))
        })
        .await
    }

    // ── HSM connections ────────────────────────────────────────────

    async fn create_hsm_connection(
        &self,
        request: Request<proto::CreateHsmConnectionRequest>,
    ) -> Result<Response<proto::CreateHsmConnectionResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let mut op_ctx = OpContext::resource(
            AuditAction::CreateHsmConnection,
            principal,
            "",
            "HsmConnection",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let conn = keyrack_core::hsm::HsmConnection::new(
                uuid::Uuid::new_v4().to_string(),
                hsm_provider_from_proto(req.provider_type()),
                &req.endpoint,
                "",
            );
            state
                .storage
                .create_hsm_connection(&conn)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::CreateHsmConnectionResponse {
                metadata: Some(hsm_connection_to_proto(&conn)),
            }))
        })
        .await
    }

    async fn get_hsm_connection(
        &self,
        request: Request<proto::GetHsmConnectionRequest>,
    ) -> Result<Response<proto::GetHsmConnectionResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let conn_id = request.into_inner().connection_id;
        let mut op_ctx = OpContext::resource(
            AuditAction::GetHsmConnection,
            principal,
            &conn_id,
            "HsmConnection",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let conn = state
                .storage
                .get_hsm_connection(&conn_id)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::GetHsmConnectionResponse {
                metadata: Some(hsm_connection_to_proto(&conn)),
            }))
        })
        .await
    }

    async fn list_hsm_connections(
        &self,
        request: Request<proto::ListHsmConnectionsRequest>,
    ) -> Result<Response<proto::ListHsmConnectionsResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let _req = request.into_inner();
        let mut op_ctx = OpContext::resource(
            AuditAction::ListHsmConnections,
            principal,
            "*",
            "HsmConnection",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let conns = state
                .storage
                .list_hsm_connections()
                .await
                .map_err(convert::error_to_status)?;
            let connections = conns.iter().map(hsm_connection_to_proto).collect();
            Ok(Response::new(proto::ListHsmConnectionsResponse {
                connections,
                next_cursor: String::new(),
            }))
        })
        .await
    }

    async fn delete_hsm_connection(
        &self,
        request: Request<proto::DeleteHsmConnectionRequest>,
    ) -> Result<Response<proto::DeleteHsmConnectionResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let conn_id = request.into_inner().connection_id;
        let mut op_ctx = OpContext::resource(
            AuditAction::DeleteHsmConnection,
            principal,
            &conn_id,
            "HsmConnection",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            state
                .storage
                .delete_hsm_connection(&conn_id)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::DeleteHsmConnectionResponse {}))
        })
        .await
    }

    async fn get_hsm_connection_status(
        &self,
        request: Request<proto::GetHsmConnectionStatusRequest>,
    ) -> Result<Response<proto::GetHsmConnectionStatusResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let conn_id = request.into_inner().connection_id;
        let mut op_ctx = OpContext::resource(
            AuditAction::GetHsmConnectionStatus,
            principal,
            &conn_id,
            "HsmConnection",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let conn = state
                .storage
                .get_hsm_connection(&conn_id)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::GetHsmConnectionStatusResponse {
                connection_id: conn.connection_id,
                status: hsm_status_to_proto(conn.status).into(),
                last_check: conn
                    .last_health_check_at
                    .map(|dt| convert::datetime_to_timestamp(&dt)),
            }))
        })
        .await
    }

    // ── Namespaces ────────────────────────────────────────────────

    async fn register_namespace(
        &self,
        request: Request<proto::RegisterNamespaceRequest>,
    ) -> Result<Response<proto::RegisterNamespaceResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let name = req.name.clone();
        let mut op_ctx = OpContext::resource(
            AuditAction::RegisterNamespace,
            principal,
            &name,
            "Namespace",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |_state| async move {
            tracing::info!(name, "namespace registered (in-memory only)");
            Ok(Response::new(proto::RegisterNamespaceResponse { name }))
        })
        .await
    }

    async fn list_namespaces(
        &self,
        request: Request<proto::ListNamespacesRequest>,
    ) -> Result<Response<proto::ListNamespacesResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let _req = request.into_inner();
        let mut op_ctx =
            OpContext::resource(AuditAction::ListNamespaces, principal, "*", "Namespace");
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |_state| async move {
            Ok(Response::new(proto::ListNamespacesResponse {
                names: vec![],
            }))
        })
        .await
    }

    async fn describe_namespace(
        &self,
        request: Request<proto::DescribeNamespaceRequest>,
    ) -> Result<Response<proto::DescribeNamespaceResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let name = request.into_inner().name;
        let mut op_ctx = OpContext::resource(
            AuditAction::DescribeNamespace,
            principal,
            &name,
            "Namespace",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |_state| async move {
            Err(Status::not_found(format!(
                "namespace '{name}' not found (namespace registry pending)"
            )))
        })
        .await
    }

    // ── Rotation jobs ─────────────────────────────────────────────

    #[allow(clippy::cast_possible_truncation)]
    async fn list_rotation_jobs(
        &self,
        request: Request<proto::ListRotationJobsRequest>,
    ) -> Result<Response<proto::ListRotationJobsResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let mut op_ctx =
            OpContext::resource(AuditAction::ListRotationJobs, principal, "*", "RotationJob");
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let state_filter = req
                .state_filter
                .and_then(|s| proto::RotationJobState::try_from(s).ok())
                .and_then(rotation_job_state_from_proto);
            let key_filter_lid = req.key_id.and_then(|k| parse_lid(&k).ok());
            let mut jobs = state
                .storage
                .list_rotation_jobs(state_filter)
                .await
                .map_err(convert::error_to_status)?;
            if let Some(lid) = &key_filter_lid {
                jobs.retain(|j| j.parent_lid == *lid || j.dependent_lid == *lid);
            }
            let job_list = jobs.iter().map(rotation_job_to_proto).collect();
            Ok(Response::new(proto::ListRotationJobsResponse {
                jobs: job_list,
                next_cursor: String::new(),
            }))
        })
        .await
    }

    async fn acknowledge_rotation_job(
        &self,
        request: Request<proto::AcknowledgeRotationJobRequest>,
    ) -> Result<Response<proto::AcknowledgeRotationJobResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let job_id = request.into_inner().job_id;
        let mut op_ctx = OpContext::resource(
            AuditAction::AcknowledgeRotationJob,
            principal,
            &job_id,
            "RotationJob",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let mut job = state
                .storage
                .get_rotation_job(&job_id)
                .await
                .map_err(convert::error_to_status)?;
            job.transition_to(keyrack_core::rotation::RotationJobState::Acknowledged)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            state
                .storage
                .update_rotation_job(&job)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::AcknowledgeRotationJobResponse {
                job: Some(rotation_job_to_proto(&job)),
            }))
        })
        .await
    }

    async fn complete_rotation_job(
        &self,
        request: Request<proto::CompleteRotationJobRequest>,
    ) -> Result<Response<proto::CompleteRotationJobResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let job_id = request.into_inner().job_id;
        let mut op_ctx = OpContext::resource(
            AuditAction::CompleteRotationJob,
            principal,
            &job_id,
            "RotationJob",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let mut job = state
                .storage
                .get_rotation_job(&job_id)
                .await
                .map_err(convert::error_to_status)?;
            job.transition_to(keyrack_core::rotation::RotationJobState::Completed)
                .map_err(|(from, to)| {
                    Status::failed_precondition(format!("cannot transition from {from} to {to}"))
                })?;
            state
                .storage
                .update_rotation_job(&job)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::CompleteRotationJobResponse {
                job: Some(rotation_job_to_proto(&job)),
            }))
        })
        .await
    }

    async fn fail_rotation_job(
        &self,
        request: Request<proto::FailRotationJobRequest>,
    ) -> Result<Response<proto::FailRotationJobResponse>, Status> {
        let request_id = Self::request_id(&request);
        let principal = self.principal(&request).await;
        let req = request.into_inner();
        let job_id = req.job_id.clone();
        let mut op_ctx = OpContext::resource(
            AuditAction::FailRotationJob,
            principal,
            &job_id,
            "RotationJob",
        );
        op_ctx.request_id = request_id;
        ops::execute(&self.state, op_ctx, |state| async move {
            let mut job = state
                .storage
                .get_rotation_job(&req.job_id)
                .await
                .map_err(convert::error_to_status)?;
            job.fail(&req.reason).map_err(|(from, to)| {
                Status::failed_precondition(format!("cannot transition from {from} to {to}"))
            })?;
            state
                .storage
                .update_rotation_job(&job)
                .await
                .map_err(convert::error_to_status)?;
            Ok(Response::new(proto::FailRotationJobResponse {
                job: Some(rotation_job_to_proto(&job)),
            }))
        })
        .await
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
        proto::HsmProviderType::Hyok => keyrack_core::hsm::HsmProviderType::Hyok,
        proto::HsmProviderType::Hsm | proto::HsmProviderType::Unspecified => {
            keyrack_core::hsm::HsmProviderType::Hsm
        }
    }
}

fn hsm_status_to_proto(
    status: keyrack_core::hsm::HsmConnectionStatus,
) -> proto::HsmConnectionStatus {
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

fn hsm_connection_to_proto(
    conn: &keyrack_core::hsm::HsmConnection,
) -> proto::HsmConnectionMetadata {
    proto::HsmConnectionMetadata {
        connection_id: conn.connection_id.clone(),
        provider_type: hsm_provider_to_proto(conn.provider_type).into(),
        endpoint: conn.endpoint.clone(),
        status: hsm_status_to_proto(conn.status).into(),
        created_at: Some(convert::datetime_to_timestamp(&conn.created_at)),
        last_health_check: conn
            .last_health_check_at
            .map(|dt| convert::datetime_to_timestamp(&dt)),
    }
}

fn rotation_job_state_to_proto(
    state: keyrack_core::rotation::RotationJobState,
) -> proto::RotationJobState {
    match state {
        keyrack_core::rotation::RotationJobState::Pending => proto::RotationJobState::Pending,
        keyrack_core::rotation::RotationJobState::Acknowledged => {
            proto::RotationJobState::Acknowledged
        }
        keyrack_core::rotation::RotationJobState::Completed => proto::RotationJobState::Completed,
        keyrack_core::rotation::RotationJobState::Failed => proto::RotationJobState::Failed,
        keyrack_core::rotation::RotationJobState::Expired => proto::RotationJobState::Expired,
    }
}

fn rotation_job_state_from_proto(
    state: proto::RotationJobState,
) -> Option<keyrack_core::rotation::RotationJobState> {
    match state {
        proto::RotationJobState::Pending => Some(keyrack_core::rotation::RotationJobState::Pending),
        proto::RotationJobState::Acknowledged => {
            Some(keyrack_core::rotation::RotationJobState::Acknowledged)
        }
        proto::RotationJobState::Completed => {
            Some(keyrack_core::rotation::RotationJobState::Completed)
        }
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
        dependent_key_id: job.dependent_lid.to_string(),
    }
}
