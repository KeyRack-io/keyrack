// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed development context. Never advertised as a production A3 capability.
use keyrack_core::{
    custody::{CustodyContext, CustodyProfile, ExecutionBoundary},
    key::{KeySpec, ProviderRef},
    lid::Lid,
    wrapping::{
        VersionedKeyId, WrappedKeyFormat, WrappingContext, WrappingContextVersion,
        WrappingIdentifier, WrappingKeyPurpose,
    },
};

pub(crate) fn custody_context(wrapping: &WrappingContext) -> CustodyContext {
    CustodyContext {
        wrapping: wrapping.clone(),
        profile: CustodyProfile {
            boundary: ExecutionBoundary::TrustedHostWorkerMemory,
            id: WrappingIdentifier::new("UNQUALIFIED-vault-derived-worker-fixture-v1").unwrap(),
        },
    }
}

pub(crate) fn context() -> WrappingContext {
    WrappingContext {
        version: WrappingContextVersion::V1,
        child: VersionedKeyId::new(Lid::from_bytes([1; 32]), 1).unwrap(),
        parent: VersionedKeyId::new(Lid::from_bytes([2; 32]), 1).unwrap(),
        parent_spec: KeySpec::Aes256,
        child_spec: KeySpec::Aes256,
        key_format: WrappedKeyFormat::RawSecret,
        purpose: WrappingKeyPurpose::EncryptDecrypt,
        provider_ref: ProviderRef::new("worker-development-fixture"),
        security_domain: WrappingIdentifier::new("development-only").unwrap(),
        mechanism: WrappingIdentifier::new("unapproved-worker-test-adapter").unwrap(),
        public_material_sha256: None,
    }
}
