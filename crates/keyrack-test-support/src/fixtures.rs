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

//! Shared test fixtures for constructing test objects.

use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::key::{
    KeyOrigin, KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord, ProviderClass,
};
use keyrack_core::lid::Lid;
use keyrack_core::provider::KeyHandle;
use keyrack_core::tags::{IdentityTags, UserTags};

/// Create a LID from a simple name (for test convenience).
pub fn test_lid(name: &str) -> Lid {
    let mut attrs = AttributeSet::new();
    attrs.insert("name", AttributeValue::String(name.into()));
    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    Lid::derive(CanonicalizationVersion::V1, &form)
}

/// Create a test `KeyRecord` in the given state.
pub fn test_key_record(state: KeyState) -> KeyRecord {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("test-tenant".into()));
    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(CanonicalizationVersion::V1, &form);

    KeyRecord {
        lid,
        canonicalization_version: CanonicalizationVersion::V1,
        parent_lid: None,
        occ_version: 1,
        current_key_version: 1,
        state,
        key_usage: KeyUsage::EncryptDecrypt,
        key_spec: KeySpec::Aes256,
        origin: KeyOrigin::KeyRack,
        provider_class: ProviderClass::Software,
        identity_tags: IdentityTags::from_attribute_set(&attrs),
        user_tags: UserTags::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        scheduled_deletion_at: None,
        description: String::new(),
        key_versions: vec![KeyVersionRecord {
            version_number: 1,
            key_handle: KeyHandle {
                key_id: "test-handle".into(),
                key_spec: KeySpec::Aes256,
            },
            created_at: chrono::Utc::now(),
            is_primary: true,
        }],
    }
}
