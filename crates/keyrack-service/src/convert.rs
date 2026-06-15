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

//! Conversions between proto types and `keyrack-core` domain types.

use crate::proto;
use keyrack_core::key::{KeyRecord, KeyState};
use prost_types::Timestamp;

pub fn key_state_to_proto(state: &KeyState) -> proto::KeyState {
    match state {
        KeyState::Creating => proto::KeyState::Creating,
        KeyState::Enabled => proto::KeyState::Enabled,
        KeyState::Disabled => proto::KeyState::Disabled,
        KeyState::Compromised => proto::KeyState::Compromised,
        KeyState::PendingDeletion => proto::KeyState::PendingDeletion,
        KeyState::Destroyed => proto::KeyState::Destroyed,
    }
}

pub fn proto_to_key_spec(spec: proto::KeySpec) -> Option<keyrack_core::key::KeySpec> {
    match spec {
        proto::KeySpec::Aes256 => Some(keyrack_core::key::KeySpec::Aes256),
        proto::KeySpec::Ed25519 => Some(keyrack_core::key::KeySpec::Ed25519),
        proto::KeySpec::Rsa2048 => {
            Some(keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 })
        }
        proto::KeySpec::Rsa3072 => {
            Some(keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 })
        }
        proto::KeySpec::Rsa4096 => {
            Some(keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 })
        }
        proto::KeySpec::EcdsaP256 => Some(keyrack_core::key::KeySpec::EcdsaP256Sha256),
        proto::KeySpec::RsaPss2048 => {
            Some(keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 2048 })
        }
        proto::KeySpec::RsaPss3072 => {
            Some(keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 3072 })
        }
        proto::KeySpec::RsaPss4096 => {
            Some(keyrack_core::key::KeySpec::RsaPssSha256 { key_size: 4096 })
        }
        proto::KeySpec::EccNistP384 => Some(keyrack_core::key::KeySpec::EcdsaP384),
        proto::KeySpec::Hmac256 => Some(keyrack_core::key::KeySpec::Hmac256),
        proto::KeySpec::Aes128 => Some(keyrack_core::key::KeySpec::Aes128),
        proto::KeySpec::Unspecified => None,
    }
}

pub fn key_spec_to_proto(spec: &keyrack_core::key::KeySpec) -> proto::KeySpec {
    match spec {
        keyrack_core::key::KeySpec::Aes256 => proto::KeySpec::Aes256,
        keyrack_core::key::KeySpec::Ed25519 => proto::KeySpec::Ed25519,
        keyrack_core::key::KeySpec::RsaPkcs1v15Sha256 { key_size } => match key_size {
            3072 => proto::KeySpec::Rsa3072,
            4096 => proto::KeySpec::Rsa4096,
            _ => proto::KeySpec::Rsa2048,
        },
        keyrack_core::key::KeySpec::EcdsaP256Sha256 => proto::KeySpec::EcdsaP256,
        keyrack_core::key::KeySpec::RsaPssSha256 { key_size } => match key_size {
            3072 => proto::KeySpec::RsaPss3072,
            4096 => proto::KeySpec::RsaPss4096,
            _ => proto::KeySpec::RsaPss2048,
        },
        keyrack_core::key::KeySpec::EcdsaP384 => proto::KeySpec::EccNistP384,
        keyrack_core::key::KeySpec::Hmac256 => proto::KeySpec::Hmac256,
        keyrack_core::key::KeySpec::Aes128 => proto::KeySpec::Aes128,
    }
}

pub fn proto_to_signing_algorithm(
    alg: proto::SigningAlgorithm,
) -> Option<keyrack_core::provider::SigningAlgorithm> {
    match alg {
        proto::SigningAlgorithm::Ed25519Pure => {
            Some(keyrack_core::provider::SigningAlgorithm::Ed25519)
        }
        proto::SigningAlgorithm::RsaPkcs1V15Sha256 => {
            Some(keyrack_core::provider::SigningAlgorithm::RsaPkcs1v15Sha256)
        }
        proto::SigningAlgorithm::EcdsaP256Sha256 => {
            Some(keyrack_core::provider::SigningAlgorithm::EcdsaP256Sha256)
        }
        proto::SigningAlgorithm::RsaPssSha256 => {
            Some(keyrack_core::provider::SigningAlgorithm::RsaPssSha256)
        }
        proto::SigningAlgorithm::RsaPkcs1V15Sha384 => {
            Some(keyrack_core::provider::SigningAlgorithm::RsaPkcs1v15Sha384)
        }
        proto::SigningAlgorithm::RsaPkcs1V15Sha512 => {
            Some(keyrack_core::provider::SigningAlgorithm::RsaPkcs1v15Sha512)
        }
        proto::SigningAlgorithm::RsaPssSha384 => {
            Some(keyrack_core::provider::SigningAlgorithm::RsaPssSha384)
        }
        proto::SigningAlgorithm::RsaPssSha512 => {
            Some(keyrack_core::provider::SigningAlgorithm::RsaPssSha512)
        }
        proto::SigningAlgorithm::EcdsaP256Sha384 => {
            Some(keyrack_core::provider::SigningAlgorithm::EcdsaP256Sha384)
        }
        proto::SigningAlgorithm::EcdsaP384Sha384 => {
            Some(keyrack_core::provider::SigningAlgorithm::EcdsaP384Sha384)
        }
        proto::SigningAlgorithm::Unspecified => None,
    }
}

pub fn signing_algorithm_to_proto(
    alg: &keyrack_core::provider::SigningAlgorithm,
) -> proto::SigningAlgorithm {
    match alg {
        keyrack_core::provider::SigningAlgorithm::Ed25519 => proto::SigningAlgorithm::Ed25519Pure,
        keyrack_core::provider::SigningAlgorithm::RsaPkcs1v15Sha256 => {
            proto::SigningAlgorithm::RsaPkcs1V15Sha256
        }
        keyrack_core::provider::SigningAlgorithm::EcdsaP256Sha256 => {
            proto::SigningAlgorithm::EcdsaP256Sha256
        }
        keyrack_core::provider::SigningAlgorithm::RsaPssSha256 => {
            proto::SigningAlgorithm::RsaPssSha256
        }
        keyrack_core::provider::SigningAlgorithm::RsaPkcs1v15Sha384 => {
            proto::SigningAlgorithm::RsaPkcs1V15Sha384
        }
        keyrack_core::provider::SigningAlgorithm::RsaPkcs1v15Sha512 => {
            proto::SigningAlgorithm::RsaPkcs1V15Sha512
        }
        keyrack_core::provider::SigningAlgorithm::RsaPssSha384 => {
            proto::SigningAlgorithm::RsaPssSha384
        }
        keyrack_core::provider::SigningAlgorithm::RsaPssSha512 => {
            proto::SigningAlgorithm::RsaPssSha512
        }
        keyrack_core::provider::SigningAlgorithm::EcdsaP256Sha384 => {
            proto::SigningAlgorithm::EcdsaP256Sha384
        }
        keyrack_core::provider::SigningAlgorithm::EcdsaP384Sha384 => {
            proto::SigningAlgorithm::EcdsaP384Sha384
        }
    }
}

pub fn proto_to_mac_algorithm(
    alg: proto::MacAlgorithm,
) -> Option<keyrack_core::provider::MacAlgorithm> {
    match alg {
        proto::MacAlgorithm::HmacSha256 => Some(keyrack_core::provider::MacAlgorithm::HmacSha256),
        proto::MacAlgorithm::HmacSha384 => Some(keyrack_core::provider::MacAlgorithm::HmacSha384),
        proto::MacAlgorithm::HmacSha512 => Some(keyrack_core::provider::MacAlgorithm::HmacSha512),
        proto::MacAlgorithm::Unspecified => None,
    }
}

pub fn mac_algorithm_to_proto(alg: &keyrack_core::provider::MacAlgorithm) -> proto::MacAlgorithm {
    match alg {
        keyrack_core::provider::MacAlgorithm::HmacSha256 => proto::MacAlgorithm::HmacSha256,
        keyrack_core::provider::MacAlgorithm::HmacSha384 => proto::MacAlgorithm::HmacSha384,
        keyrack_core::provider::MacAlgorithm::HmacSha512 => proto::MacAlgorithm::HmacSha512,
    }
}

pub fn proto_to_key_usage(usage: proto::KeyUsage) -> Option<keyrack_core::key::KeyUsage> {
    match usage {
        proto::KeyUsage::EncryptDecrypt => Some(keyrack_core::key::KeyUsage::EncryptDecrypt),
        proto::KeyUsage::SignVerify => Some(keyrack_core::key::KeyUsage::SignVerify),
        proto::KeyUsage::GenerateVerifyMac => Some(keyrack_core::key::KeyUsage::GenerateVerifyMac),
        proto::KeyUsage::Unspecified => None,
    }
}

pub fn key_usage_to_proto(usage: keyrack_core::key::KeyUsage) -> proto::KeyUsage {
    match usage {
        keyrack_core::key::KeyUsage::EncryptDecrypt => proto::KeyUsage::EncryptDecrypt,
        keyrack_core::key::KeyUsage::SignVerify => proto::KeyUsage::SignVerify,
        keyrack_core::key::KeyUsage::GenerateVerifyMac => proto::KeyUsage::GenerateVerifyMac,
    }
}

#[allow(clippy::cast_possible_wrap)]
pub fn datetime_to_timestamp(dt: &chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn key_record_to_metadata(record: &KeyRecord) -> proto::KeyMetadata {
    let user_tags = record
        .user_tags
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    proto::KeyMetadata {
        key_id: record.lid.to_string(),
        key_spec: key_spec_to_proto(&record.key_spec).into(),
        key_usage: key_usage_to_proto(record.key_usage).into(),
        state: key_state_to_proto(&record.state).into(),
        origin: match record.origin {
            keyrack_core::key::KeyOrigin::KeyRack => proto::KeyOrigin::Keyrack.into(),
            keyrack_core::key::KeyOrigin::External => proto::KeyOrigin::External.into(),
        },
        description: record.description.clone(),
        created_at: Some(datetime_to_timestamp(&record.created_at)),
        current_key_version: record.current_key_version as u32,
        user_tags,
        parent_key_id: record.parent_lid.map(|l| l.to_string()),
        hsm_connection_id: None,
        occ_version: record.occ_version,
        scheduled_deletion_at: record
            .scheduled_deletion_at
            .as_ref()
            .map(datetime_to_timestamp),
    }
}

#[allow(clippy::cast_possible_truncation)]
pub fn key_version_to_proto(v: &keyrack_core::key::KeyVersionRecord) -> proto::KeyVersionMetadata {
    proto::KeyVersionMetadata {
        version: v.version_number as u32,
        created_at: Some(datetime_to_timestamp(&v.created_at)),
        state: if v.is_primary {
            proto::KeyState::Enabled.into()
        } else {
            proto::KeyState::Disabled.into()
        },
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn error_to_status(err: keyrack_core::error::KeyRackError) -> tonic::Status {
    use keyrack_core::error::KeyRackError;
    let msg = err.to_string();
    match err {
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
        KeyRackError::CascadeDisableFailed { .. }
        | KeyRackError::Provider(_)
        | KeyRackError::Storage(_)
        | KeyRackError::Other(_) => tonic::Status::internal(msg),
    }
}
