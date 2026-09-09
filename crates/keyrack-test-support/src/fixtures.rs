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

//! Shared test fixtures for constructing test objects.

use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::key::{
    KeyMaterial, KeyOrigin, KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord,
    ParentWrappedMaterial, ProviderClass, ProviderRef,
};
use keyrack_core::lid::Lid;
use keyrack_core::provider::KeyHandle;
use keyrack_core::tags::{IdentityTags, UserTags};
use keyrack_core::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappingContextVersion, WrappingIdentifier,
};

/// Create a LID from a simple name (for test convenience).
pub fn test_lid(name: &str) -> Lid {
    let mut attrs = AttributeSet::new();
    attrs.insert("name", AttributeValue::String(name.into()));
    let form = canonicalize(CanonicalizationVersion::V2, &attrs).unwrap();
    Lid::derive(CanonicalizationVersion::V2, &form)
}

/// Create a test `KeyRecord` in the given state.
pub fn test_key_record(state: KeyState) -> KeyRecord {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("test-tenant".into()));
    let form = canonicalize(CanonicalizationVersion::V2, &attrs).unwrap();
    let lid = Lid::derive(CanonicalizationVersion::V2, &form);

    KeyRecord {
        lid,
        canonicalization_version: CanonicalizationVersion::V2,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state,
        was_compromised: false,
        key_usage: KeyUsage::EncryptDecrypt,
        key_spec: KeySpec::Aes256,
        origin: KeyOrigin::KeyRack,
        provider_class: ProviderClass::Software,
        provider_ref: None,
        exportability: keyrack_core::key::Exportability::default(),
        first_exported_at: None,
        owner_principal_id: None,
        identity_tags: IdentityTags::from_attribute_set(&attrs).unwrap(),
        user_tags: UserTags::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        scheduled_deletion_at: None,
        description: String::new(),
        key_versions: vec![KeyVersionRecord::provider_resident(
            1,
            KeyHandle {
                key_id: "test-handle".into(),
                key_spec: KeySpec::Aes256,
            },
            None,
            chrono::Utc::now(),
            true,
        )],
    }
}

/// A unique key fixture for tests sharing a persistent database.
/// The deterministic `test_key_record` fixture remains available separately.
pub fn unique_test_key_record(state: KeyState) -> KeyRecord {
    let mut record = test_key_record(state);
    record.lid = test_lid(&format!("storage-conformance-{}", uuid::Uuid::new_v4()));
    record
}

/// Mixed persistence fixture, not an authenticated or usable wrapping profile.
/// The resident version retains legacy binding inheritance; the wrapped version
/// has an explicit, distinct provider and no independently usable handle.
pub fn mixed_material_key_record(state: KeyState) -> KeyRecord {
    let mut record = test_key_record(state);
    record.lid = test_lid(&format!("mixed-material-{}", uuid::Uuid::new_v4()));
    record.provider_ref = Some(ProviderRef::new("resident-test-backend"));
    let parent_lid = test_lid("mixed-material-parent");
    record.parent_lid = Some(parent_lid);
    record.key_versions[0].is_primary = false;
    record.key_versions.push(KeyVersionRecord {
        version_number: 2,
        material: KeyMaterial::ParentWrapped(
            ParentWrappedMaterial::new(
                ProviderRef::new("wrapped-test-backend"),
                WrappingIdentifier::new("persistence-test-domain").unwrap(),
                VersionedKeyId::new(parent_lid, 3).unwrap(),
                WrappingContextVersion::V1,
                WrappedKeyFormat::RawSecret,
                WrappingIdentifier::new("unqualified-persistence-test").unwrap(),
                WrappingIdentifier::new("unverified-wrapped-reference-v2").unwrap(),
            )
            .unwrap(),
        ),
        created_at: record.created_at,
        is_primary: true,
    });
    record.current_key_version = 2;
    record
}
