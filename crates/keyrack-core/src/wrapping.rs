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

//! Typed wrapping context and exact capability matching.
//!
//! This module implements no wrapping primitive, key persistence, or provider
//! lifecycle. Canonical bytes are input to a separately reviewed authenticated
//! wrapping construction; they do not authenticate metadata, establish authority,
//! prevent rollback, or prove that an independently usable key object is absent.
//!
//! Version 1 is a fixed domain separator followed by big-endian numeric fields,
//! raw LID bytes, and length-prefixed identifiers in the order documented by
//! [`WrappingContext::canonical_bytes`]. Numeric tags are explicitly assigned;
//! neither Rust enum layout nor Debug/Display/serde output defines the encoding.

use crate::key::{KeySpec, ProviderRef};
use crate::lid::Lid;
use std::num::NonZeroU64;

/// Maximum encoded byte length of a provider, mechanism, format or domain name.
pub const MAX_WRAPPING_IDENTIFIER_BYTES: usize = 256;

const CONTEXT_DOMAIN: &[u8] = b"KeyRack:ParentWrappedContext\0";

/// Structural errors or an unsupported requested profile; never a fallback.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WrappingError {
    #[error("wrapping identifier must be 1..=256 printable ASCII bytes without whitespace")]
    InvalidIdentifier,
    #[error("key version must be nonzero")]
    ZeroKeyVersion,
    #[error("unsupported wrapping context version {0}")]
    UnsupportedContextVersion(u16),
    #[error("wrapping parent must have an AES key spec")]
    InvalidParentSpec,
    #[error("unsupported RSA size in wrapping context")]
    InvalidKeySpec,
    #[error("key purpose does not match the child key spec")]
    InvalidPurpose,
    #[error("key format does not match the child key spec")]
    InvalidKeyFormat,
    #[error("public-material digest must be present exactly for asymmetric keys")]
    InvalidPublicMaterialDigest,
    #[error("requested wrapping capability tuple is unsupported")]
    UnsupportedCapability,
}

/// A bounded opaque identifier, compared byte-for-byte with no normalization.
///
/// Printable ASCII excludes control characters and whitespace. Separators are
/// allowed: length prefixes, rather than delimiter interpretation, disambiguate
/// adjacent fields. An asterisk is an ordinary byte, never a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WrappingIdentifier(String);

impl WrappingIdentifier {
    pub fn new(value: impl Into<String>) -> Result<Self, WrappingError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_identifier(value: &str) -> Result<(), WrappingError> {
    if value.is_empty()
        || value.len() > MAX_WRAPPING_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(WrappingError::InvalidIdentifier);
    }
    Ok(())
}

/// An exact logical key version, distinct from a mutable primary-version alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionedKeyId {
    pub lid: Lid,
    pub version: NonZeroU64,
}

impl VersionedKeyId {
    pub fn new(lid: Lid, version: u64) -> Result<Self, WrappingError> {
        Ok(Self {
            lid,
            version: NonZeroU64::new(version).ok_or(WrappingError::ZeroKeyVersion)?,
        })
    }
}

/// Supported canonical context encodings. New encodings need a new variant/tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WrappingContextVersion {
    V1,
}

impl TryFrom<u16> for WrappingContextVersion {
    type Error = WrappingError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(WrappingError::UnsupportedContextVersion(value)),
        }
    }
}

/// Private/secret material format. Provider formats require an exact identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WrappedKeyFormat {
    /// Raw symmetric-key octets, not an asymmetric private-key encoding.
    RawSecret,
    Pkcs8Der,
    ProviderNative(WrappingIdentifier),
}

/// Intended child-key authority, which a provider must independently enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WrappingKeyPurpose {
    EncryptDecrypt,
    SignVerify,
    GenerateVerifyMac,
    WrapUnwrap,
}

/// Binding inputs supplied by a caller that has resolved exact key versions.
///
/// Construction does not establish that these values match stored/provider
/// material or that the caller is authorized. The consuming provider must check
/// those relationships and authenticate these bytes within its trust boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappingContext {
    pub version: WrappingContextVersion,
    pub child: VersionedKeyId,
    pub parent: VersionedKeyId,
    pub parent_spec: KeySpec,
    pub child_spec: KeySpec,
    pub key_format: WrappedKeyFormat,
    pub purpose: WrappingKeyPurpose,
    pub provider_ref: ProviderRef,
    /// Stable backend security-domain identity, not a mutable endpoint address.
    pub security_domain: WrappingIdentifier,
    /// Exact construction/profile identity; this module selects no mechanism.
    pub mechanism: WrappingIdentifier,
    /// SHA-256 of the public material in the representation fixed by the profile.
    /// Required for asymmetric children and absent for secret-only children.
    /// This module neither computes nor verifies the digest.
    pub public_material_sha256: Option<[u8; 32]>,
}

impl WrappingContext {
    /// Encode structurally valid context without authenticating it.
    ///
    /// Field order: domain; context version (u16); child LID/version (32/u64);
    /// parent LID/version; parent spec; child spec; format; purpose (u8);
    /// provider; security domain; mechanism; public-digest presence (u8), then
    /// digest if present. All integers are big endian. Specs/formats use fixed
    /// u8 tags; RSA specs append u32 bit size. Names use u16 byte lengths.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WrappingError> {
        self.validate()?;
        let mut bytes = CONTEXT_DOMAIN.to_vec();
        match self.version {
            WrappingContextVersion::V1 => bytes.extend_from_slice(&1_u16.to_be_bytes()),
        }
        append_key_id(&mut bytes, self.child);
        append_key_id(&mut bytes, self.parent);
        append_spec(&mut bytes, &self.parent_spec);
        append_spec(&mut bytes, &self.child_spec);
        match &self.key_format {
            WrappedKeyFormat::RawSecret => bytes.push(1),
            WrappedKeyFormat::Pkcs8Der => bytes.push(2),
            WrappedKeyFormat::ProviderNative(name) => {
                bytes.push(3);
                append_identifier(&mut bytes, name.as_str());
            }
        }
        bytes.push(match self.purpose {
            WrappingKeyPurpose::EncryptDecrypt => 1,
            WrappingKeyPurpose::SignVerify => 2,
            WrappingKeyPurpose::GenerateVerifyMac => 3,
            WrappingKeyPurpose::WrapUnwrap => 4,
        });
        append_identifier(&mut bytes, self.provider_ref.as_str());
        append_identifier(&mut bytes, self.security_domain.as_str());
        append_identifier(&mut bytes, self.mechanism.as_str());
        match self.public_material_sha256 {
            None => bytes.push(0),
            Some(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest);
            }
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), WrappingError> {
        validate_identifier(self.provider_ref.as_str())?;
        validate_profile(
            &self.parent_spec,
            &self.child_spec,
            &self.key_format,
            self.purpose,
        )?;
        if is_asymmetric(&self.child_spec) != self.public_material_sha256.is_some() {
            return Err(WrappingError::InvalidPublicMaterialDigest);
        }
        Ok(())
    }
}

fn append_key_id(bytes: &mut Vec<u8>, id: VersionedKeyId) {
    bytes.extend_from_slice(id.lid.as_bytes());
    bytes.extend_from_slice(&id.version.get().to_be_bytes());
}

fn append_identifier(bytes: &mut Vec<u8>, value: &str) {
    // Every caller validates the 256-byte bound before encoding.
    let length = u16::try_from(value.len()).expect("validated identifier length fits u16");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn append_spec(bytes: &mut Vec<u8>, spec: &KeySpec) {
    match spec {
        KeySpec::Aes256 => bytes.push(1),
        KeySpec::Aes128 => bytes.push(2),
        KeySpec::Ed25519 => bytes.push(3),
        KeySpec::RsaPkcs1v15Sha256 { key_size } => {
            bytes.push(4);
            bytes.extend_from_slice(&key_size.to_be_bytes());
        }
        KeySpec::RsaPssSha256 { key_size } => {
            bytes.push(5);
            bytes.extend_from_slice(&key_size.to_be_bytes());
        }
        KeySpec::EcdsaP256Sha256 => bytes.push(6),
        KeySpec::EcdsaP384 => bytes.push(7),
        KeySpec::Hmac256 => bytes.push(8),
    }
}

fn is_asymmetric(spec: &KeySpec) -> bool {
    !matches!(spec, KeySpec::Aes256 | KeySpec::Aes128 | KeySpec::Hmac256)
}

fn validate_profile(
    parent: &KeySpec,
    child: &KeySpec,
    format: &WrappedKeyFormat,
    purpose: WrappingKeyPurpose,
) -> Result<(), WrappingError> {
    if !matches!(parent, KeySpec::Aes256 | KeySpec::Aes128) {
        return Err(WrappingError::InvalidParentSpec);
    }
    if let KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } = child {
        if !matches!(key_size, 2048 | 3072 | 4096) {
            return Err(WrappingError::InvalidKeySpec);
        }
    }
    let valid_purpose = match child {
        KeySpec::Aes256 | KeySpec::Aes128 => matches!(
            purpose,
            WrappingKeyPurpose::EncryptDecrypt | WrappingKeyPurpose::WrapUnwrap
        ),
        KeySpec::Hmac256 => purpose == WrappingKeyPurpose::GenerateVerifyMac,
        _ => purpose == WrappingKeyPurpose::SignVerify,
    };
    if !valid_purpose {
        return Err(WrappingError::InvalidPurpose);
    }
    match format {
        WrappedKeyFormat::RawSecret if is_asymmetric(child) => Err(WrappingError::InvalidKeyFormat),
        WrappedKeyFormat::Pkcs8Der if !is_asymmetric(child) => Err(WrappingError::InvalidKeyFormat),
        _ => Ok(()),
    }
}

/// Hierarchy operations are separate from ordinary data-key/re-encrypt APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappingOperation {
    Generate,
    Open,
    Close,
    Rewrap,
}

/// Object lifetime that the provider's conformance profile must establish.
/// Neither variant asserts hardware isolation, erasure or authorization freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedKeyLifecycle {
    SessionObject,
    JournaledTemporaryObject,
}

/// One exact supported profile; no field is a wildcard or a strength ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappingCapability {
    pub parent_spec: KeySpec,
    pub child_spec: KeySpec,
    pub key_format: WrappedKeyFormat,
    pub purpose: WrappingKeyPurpose,
    pub mechanism: WrappingIdentifier,
    pub context_version: WrappingContextVersion,
    pub operation: WrappingOperation,
    pub lifecycle: WrappedKeyLifecycle,
}

impl WrappingCapability {
    fn validate(&self) -> Result<(), WrappingError> {
        validate_profile(
            &self.parent_spec,
            &self.child_spec,
            &self.key_format,
            self.purpose,
        )
    }
}

/// A declaration, not a conformance proof. Legacy providers default to empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WrappingCapabilities {
    tuples: Vec<WrappingCapability>,
}

impl WrappingCapabilities {
    /// Validate declarations structurally. Providers still need conformance tests.
    pub fn new(tuples: Vec<WrappingCapability>) -> Result<Self, WrappingError> {
        for tuple in &tuples {
            tuple.validate()?;
        }
        Ok(Self { tuples })
    }

    #[must_use]
    pub fn tuples(&self) -> &[WrappingCapability] {
        &self.tuples
    }

    /// Match every field exactly. Unsupported requests never select a fallback.
    pub fn require(&self, requested: &WrappingCapability) -> Result<(), WrappingError> {
        requested.validate()?;
        if self.tuples.contains(requested) {
            Ok(())
        } else {
            Err(WrappingError::UnsupportedCapability)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{inmem::InMemoryProvider, software::SoftwareProvider, CryptoProvider};
    use proptest::prelude::*;

    fn name(value: &str) -> WrappingIdentifier {
        WrappingIdentifier::new(value).unwrap()
    }

    fn context() -> WrappingContext {
        WrappingContext {
            version: WrappingContextVersion::V1,
            child: VersionedKeyId::new(Lid::from_bytes([1; 32]), 1).unwrap(),
            parent: VersionedKeyId::new(Lid::from_bytes([2; 32]), 2).unwrap(),
            parent_spec: KeySpec::Aes256,
            child_spec: KeySpec::Aes256,
            key_format: WrappedKeyFormat::RawSecret,
            purpose: WrappingKeyPurpose::EncryptDecrypt,
            provider_ref: ProviderRef::new("p"),
            security_domain: name("d"),
            mechanism: name("m"),
            public_material_sha256: None,
        }
    }

    fn tuple() -> WrappingCapability {
        WrappingCapability {
            parent_spec: KeySpec::Aes256,
            child_spec: KeySpec::Aes256,
            key_format: WrappedKeyFormat::RawSecret,
            purpose: WrappingKeyPurpose::EncryptDecrypt,
            mechanism: name("m"),
            context_version: WrappingContextVersion::V1,
            operation: WrappingOperation::Open,
            lifecycle: WrappedKeyLifecycle::SessionObject,
        }
    }

    #[test]
    fn version_one_encoding_is_pinned() {
        let mut expected = b"KeyRack:ParentWrappedContext\0\x00\x01".to_vec();
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        expected.extend_from_slice(b"\x01\x01\x01\x01\x00\x01p\x00\x01d\x00\x01m\x00");
        assert_eq!(context().canonical_bytes().unwrap(), expected);
    }

    #[test]
    fn key_spec_tags_and_rsa_parameters_are_pinned() {
        let cases: Vec<(KeySpec, Vec<u8>)> = vec![
            (KeySpec::Aes256, vec![1]),
            (KeySpec::Aes128, vec![2]),
            (KeySpec::Ed25519, vec![3]),
            (
                KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                vec![4, 0, 0, 8, 0],
            ),
            (
                KeySpec::RsaPkcs1v15Sha256 { key_size: 3072 },
                vec![4, 0, 0, 12, 0],
            ),
            (
                KeySpec::RsaPkcs1v15Sha256 { key_size: 4096 },
                vec![4, 0, 0, 16, 0],
            ),
            (
                KeySpec::RsaPssSha256 { key_size: 2048 },
                vec![5, 0, 0, 8, 0],
            ),
            (
                KeySpec::RsaPssSha256 { key_size: 3072 },
                vec![5, 0, 0, 12, 0],
            ),
            (
                KeySpec::RsaPssSha256 { key_size: 4096 },
                vec![5, 0, 0, 16, 0],
            ),
            (KeySpec::EcdsaP256Sha256, vec![6]),
            (KeySpec::EcdsaP384, vec![7]),
            (KeySpec::Hmac256, vec![8]),
        ];
        let mut encoded_contexts = std::collections::HashSet::new();
        for (spec, expected) in cases {
            let mut bytes = Vec::new();
            append_spec(&mut bytes, &spec);
            assert_eq!(bytes, expected);

            let mut ctx = context();
            if is_asymmetric(&spec) {
                ctx.key_format = WrappedKeyFormat::Pkcs8Der;
                ctx.purpose = WrappingKeyPurpose::SignVerify;
                ctx.public_material_sha256 = Some([3; 32]);
            } else if spec == KeySpec::Hmac256 {
                ctx.purpose = WrappingKeyPurpose::GenerateVerifyMac;
            }
            ctx.child_spec = spec;
            assert!(encoded_contexts.insert(ctx.canonical_bytes().unwrap()));
        }
    }

    #[test]
    fn native_format_names_are_exact_and_bounded() {
        let mut ctx = context();
        ctx.key_format = WrappedKeyFormat::ProviderNative(name("native:v1"));
        let bytes = ctx.canonical_bytes().unwrap();
        ctx.key_format = WrappedKeyFormat::ProviderNative(name("Native:v1"));
        assert_ne!(bytes, ctx.canonical_bytes().unwrap());

        let max_name = "x".repeat(MAX_WRAPPING_IDENTIFIER_BYTES);
        ctx.key_format = WrappedKeyFormat::ProviderNative(name(&max_name));
        ctx.provider_ref = ProviderRef::new(&max_name);
        ctx.security_domain = name(&max_name);
        ctx.mechanism = name(&max_name);
        assert!(ctx.canonical_bytes().is_ok());
        assert!(VersionedKeyId::new(ctx.child.lid, u64::MAX).is_ok());
    }

    #[test]
    fn every_context_binding_changes_bytes() {
        let original = context();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.child.lid = Lid::from_bytes([3; 32]);
        variants.push(changed);
        let mut changed = original.clone();
        changed.child.version = NonZeroU64::new(3).unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.parent.lid = Lid::from_bytes([3; 32]);
        variants.push(changed);
        let mut changed = original.clone();
        changed.parent.version = NonZeroU64::new(3).unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.parent_spec = KeySpec::Aes128;
        variants.push(changed);
        let mut changed = original.clone();
        changed.child_spec = KeySpec::Aes128;
        variants.push(changed);
        let mut changed = original.clone();
        changed.key_format = WrappedKeyFormat::ProviderNative(name("format-v1"));
        variants.push(changed);
        let mut changed = original.clone();
        changed.purpose = WrappingKeyPurpose::WrapUnwrap;
        variants.push(changed);
        let mut changed = original.clone();
        changed.provider_ref = ProviderRef::new("other");
        variants.push(changed);
        let mut changed = original.clone();
        changed.security_domain = name("other");
        variants.push(changed);
        let mut changed = original.clone();
        changed.mechanism = name("other");
        variants.push(changed);
        let bytes = original.canonical_bytes().unwrap();
        for changed in variants {
            assert_ne!(changed.canonical_bytes().unwrap(), bytes);
        }
        let mut asymmetric = original;
        asymmetric.child_spec = KeySpec::Ed25519;
        asymmetric.purpose = WrappingKeyPurpose::SignVerify;
        asymmetric.key_format = WrappedKeyFormat::Pkcs8Der;
        asymmetric.public_material_sha256 = Some([3; 32]);
        let bytes = asymmetric.canonical_bytes().unwrap();
        asymmetric.public_material_sha256 = Some([4; 32]);
        assert_ne!(asymmetric.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn invalid_inputs_fail_closed() {
        assert_eq!(
            VersionedKeyId::new(Lid::from_bytes([0; 32]), 0),
            Err(WrappingError::ZeroKeyVersion)
        );
        for version in [0, 2, u16::MAX] {
            assert_eq!(
                WrappingContextVersion::try_from(version),
                Err(WrappingError::UnsupportedContextVersion(version))
            );
        }
        for invalid in [
            String::new(),
            "has space".into(),
            "nul\0name".into(),
            "é".into(),
            "x".repeat(MAX_WRAPPING_IDENTIFIER_BYTES + 1),
        ] {
            assert_eq!(
                WrappingIdentifier::new(invalid.clone()),
                Err(WrappingError::InvalidIdentifier)
            );
            let mut ctx = context();
            ctx.provider_ref = ProviderRef::new(invalid);
            assert_eq!(ctx.canonical_bytes(), Err(WrappingError::InvalidIdentifier));
        }
        assert!(WrappingIdentifier::new("x".repeat(MAX_WRAPPING_IDENTIFIER_BYTES)).is_ok());
        let mut ctx = context();
        ctx.public_material_sha256 = Some([0; 32]);
        assert_eq!(
            ctx.canonical_bytes(),
            Err(WrappingError::InvalidPublicMaterialDigest)
        );
        ctx.public_material_sha256 = None;
        ctx.parent_spec = KeySpec::Hmac256;
        assert_eq!(ctx.canonical_bytes(), Err(WrappingError::InvalidParentSpec));
        ctx.parent_spec = KeySpec::Aes256;
        ctx.child_spec = KeySpec::Ed25519;
        assert_eq!(ctx.canonical_bytes(), Err(WrappingError::InvalidPurpose));
        ctx.purpose = WrappingKeyPurpose::SignVerify;
        assert_eq!(ctx.canonical_bytes(), Err(WrappingError::InvalidKeyFormat));
        ctx.key_format = WrappedKeyFormat::Pkcs8Der;
        assert_eq!(
            ctx.canonical_bytes(),
            Err(WrappingError::InvalidPublicMaterialDigest)
        );
        ctx.child_spec = KeySpec::RsaPssSha256 { key_size: 0 };
        assert_eq!(ctx.canonical_bytes(), Err(WrappingError::InvalidKeySpec));
    }

    #[test]
    fn capabilities_match_every_field_and_never_fall_back() {
        let supported = tuple();
        let capabilities = WrappingCapabilities::new(vec![supported.clone()]).unwrap();
        assert_eq!(capabilities.require(&supported), Ok(()));
        let mut variants = Vec::new();
        let mut changed = supported.clone();
        changed.parent_spec = KeySpec::Aes128;
        variants.push(changed);
        let mut changed = supported.clone();
        changed.child_spec = KeySpec::Aes128;
        variants.push(changed);
        let mut changed = supported.clone();
        changed.key_format = WrappedKeyFormat::ProviderNative(name("format"));
        variants.push(changed);
        let mut changed = supported.clone();
        changed.purpose = WrappingKeyPurpose::WrapUnwrap;
        variants.push(changed);
        let mut changed = supported.clone();
        changed.mechanism = name("other");
        variants.push(changed);
        let mut changed = supported.clone();
        changed.operation = WrappingOperation::Rewrap;
        variants.push(changed);
        let mut changed = supported.clone();
        changed.lifecycle = WrappedKeyLifecycle::JournaledTemporaryObject;
        variants.push(changed);
        for changed in variants {
            assert_eq!(
                capabilities.require(&changed),
                Err(WrappingError::UnsupportedCapability)
            );
        }
        assert_eq!(
            WrappingCapabilities::default().require(&supported),
            Err(WrappingError::UnsupportedCapability)
        );
        let mut wildcard = supported.clone();
        wildcard.mechanism = name("*");
        assert_eq!(
            WrappingCapabilities::new(vec![wildcard])
                .unwrap()
                .require(&supported),
            Err(WrappingError::UnsupportedCapability)
        );
        let mut invalid = supported;
        invalid.parent_spec = KeySpec::Hmac256;
        assert_eq!(
            capabilities.require(&invalid),
            Err(WrappingError::InvalidParentSpec)
        );
        assert_eq!(
            WrappingCapabilities::new(vec![invalid]),
            Err(WrappingError::InvalidParentSpec)
        );
    }

    #[test]
    fn legacy_core_providers_advertise_no_wrapping() {
        let providers: Vec<Box<dyn CryptoProvider>> = vec![
            Box::new(SoftwareProvider::new()),
            Box::new(InMemoryProvider::new()),
        ];
        for provider in providers {
            assert!(provider.wrapping_capabilities().tuples().is_empty());
            assert_eq!(
                provider.wrapping_capabilities().require(&tuple()),
                Err(WrappingError::UnsupportedCapability)
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_versions_and_ids_bind_exactly(
            child in any::<[u8; 32]>(), parent in any::<[u8; 32]>(),
            child_version in 1_u64..u64::MAX, parent_version in 1_u64..u64::MAX,
        ) {
            let mut ctx = context();
            ctx.child = VersionedKeyId::new(Lid::from_bytes(child), child_version).unwrap();
            ctx.parent = VersionedKeyId::new(Lid::from_bytes(parent), parent_version).unwrap();
            let bytes = ctx.canonical_bytes().unwrap();
            prop_assert_eq!(&bytes, &ctx.clone().canonical_bytes().unwrap());
            ctx.child.version = NonZeroU64::new(child_version + 1).unwrap();
            prop_assert_ne!(&bytes, &ctx.canonical_bytes().unwrap());
        }

        #[test]
        fn adjacent_identifier_boundaries_are_unambiguous(a in "[a-z:]{1,40}", b in "[a-z:]{1,40}") {
            let mut left = context();
            left.provider_ref = ProviderRef::new(format!("{a}x"));
            left.security_domain = name(&b);
            let mut right = context();
            right.provider_ref = ProviderRef::new(a);
            right.security_domain = name(&format!("x{b}"));
            prop_assert_ne!(left.canonical_bytes().unwrap(), right.canonical_bytes().unwrap());
        }
    }
}
