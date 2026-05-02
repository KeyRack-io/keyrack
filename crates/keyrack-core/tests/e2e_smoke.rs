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

//! End-to-end smoke test: validates the full identity pipeline.
//!
//! This test is designed to grow with W1. Each section below maps to a
//! W1 deliverable; sections are added as the corresponding code lands.
//! The `scripts/e2e-smoke.sh` wrapper runs this test and reports results.
//!
//! Current coverage:
//!   [x] Attribute model → canonicalization → LID derivation → display → parse
//!   [x] Sensitive<T> redaction
//!   [x] Key state machine transitions
//!   [x] Tags model: identity immutability, user CRUD
//!   [x] KeyRecord lifecycle (create → enable → disable → pending_deletion → destroy)
//!   [ ] Ciphertext header encode/decode round-trip     (pending)
//!   [ ] Software provider encrypt/decrypt round-trip   (pending)
//!   [ ] Cascade-disable propagation                    (pending)
//!   [ ] Audit event emission                           (pending)

use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::error::KeyRackError;
use keyrack_core::key::{KeyRecord, KeySpec, KeyState, KeyUsage, ProviderClass};
use keyrack_core::lid::Lid;
use keyrack_core::sensitive::Sensitive;
use keyrack_core::tags::{validate_tag_mutation, IdentityTags, UserTags};
use std::collections::BTreeMap;

/// Full identity pipeline: attrs → canonical form → LID → string → parse → same LID.
///
/// Simulates the path a real request takes: a caller presents an attribute
/// set describing a key, KeyRack canonicalizes it, derives the LID, and the
/// LID round-trips through serialization boundaries (API responses, storage,
/// audit events) without corruption.
#[test]
fn identity_pipeline_round_trip() {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("acme-corp".into()));
    attrs.insert("kind", AttributeValue::String("dek".into()));
    attrs.insert("user", AttributeValue::String("alice".into()));
    attrs.insert("doc", AttributeValue::String("invoice-42".into()));

    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    assert!(!form.bytes().is_empty(), "canonical form must be non-empty");

    let lid = Lid::derive(CanonicalizationVersion::V1, &form);

    // Simulate serialization boundary (API response, database, audit event).
    let lid_string = lid.to_string();
    let lid_parsed: Lid = lid_string.parse().expect("LID string must parse");
    assert_eq!(lid, lid_parsed, "LID must survive display/parse round-trip");

    // Simulate JSON serialization (serde boundary).
    let lid_json = serde_json::to_string(&lid).expect("LID must serialize to JSON");
    let lid_from_json: Lid = serde_json::from_str(&lid_json).expect("LID must deserialize");
    assert_eq!(lid, lid_from_json, "LID must survive JSON round-trip");
}

/// Same attribute set constructed in different code paths must produce
/// the same LID — this is the fundamental determinism guarantee.
#[test]
fn identity_pipeline_determinism_across_construction_paths() {
    // Path A: insert one by one.
    let mut a = AttributeSet::new();
    a.insert("tenant", AttributeValue::String("globex".into()));
    a.insert("kind", AttributeValue::String("kek".into()));
    a.insert("region", AttributeValue::String("eu-west-1".into()));

    // Path B: from a BTreeMap constructed all at once.
    let mut map = BTreeMap::new();
    map.insert("kind".into(), AttributeValue::String("kek".into()));
    map.insert("tenant".into(), AttributeValue::String("globex".into()));
    map.insert("region".into(), AttributeValue::String("eu-west-1".into()));
    let b = AttributeSet::from(map);

    let form_a = canonicalize(CanonicalizationVersion::V1, &a);
    let form_b = canonicalize(CanonicalizationVersion::V1, &b);
    assert_eq!(
        form_a.bytes(),
        form_b.bytes(),
        "same attributes must canonicalize identically regardless of construction order"
    );

    let lid_a = Lid::derive(CanonicalizationVersion::V1, &form_a);
    let lid_b = Lid::derive(CanonicalizationVersion::V1, &form_b);
    assert_eq!(lid_a, lid_b, "same attributes must produce the same LID");
}

/// NFC normalization is part of the identity contract: equivalent Unicode
/// representations must hash to the same LID.
#[test]
fn identity_pipeline_unicode_normalization() {
    // Precomposed é (U+00E9).
    let mut composed = AttributeSet::new();
    composed.insert("name", AttributeValue::String("\u{00e9}milie".into()));

    // Decomposed e + combining acute (U+0065 U+0301).
    let mut decomposed = AttributeSet::new();
    decomposed.insert("name", AttributeValue::String("e\u{0301}milie".into()));

    let lid_composed = Lid::derive(
        CanonicalizationVersion::V1,
        &canonicalize(CanonicalizationVersion::V1, &composed),
    );
    let lid_decomposed = Lid::derive(
        CanonicalizationVersion::V1,
        &canonicalize(CanonicalizationVersion::V1, &decomposed),
    );

    assert_eq!(
        lid_composed, lid_decomposed,
        "NFC-equivalent strings must produce the same LID"
    );
}

/// Nested records and list-of-string round-trip through the full pipeline.
#[test]
fn identity_pipeline_complex_attributes() {
    let mut extra = BTreeMap::new();
    extra.insert("env".into(), AttributeValue::String("production".into()));
    extra.insert("priority".into(), AttributeValue::I64(1));

    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("acme".into()));
    attrs.insert("kind", AttributeValue::String("signing-key".into()));
    attrs.insert("algorithms", AttributeValue::ListOfString(vec![
        "ed25519".into(),
        "ecdsa-p256".into(),
    ]));
    attrs.insert("extra", AttributeValue::Record(extra));
    attrs.insert("active", AttributeValue::Bool(true));

    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(CanonicalizationVersion::V1, &form);

    // Must survive the full serialization gauntlet.
    let s = lid.to_string();
    assert_eq!(lid, s.parse::<Lid>().unwrap());

    let json = serde_json::to_string(&lid).unwrap();
    assert_eq!(lid, serde_json::from_str::<Lid>(&json).unwrap());

    // Re-derive from the same attributes — determinism check.
    let lid2 = Lid::derive(
        CanonicalizationVersion::V1,
        &canonicalize(CanonicalizationVersion::V1, &attrs),
    );
    assert_eq!(lid, lid2);
}

/// Different attribute sets produce different LIDs (non-collision for the
/// most security-relevant case: same tenant, different key kind).
#[test]
fn identity_pipeline_distinct_keys() {
    let make = |kind: &str| {
        let mut a = AttributeSet::new();
        a.insert("tenant", AttributeValue::String("acme".into()));
        a.insert("kind", AttributeValue::String(kind.into()));
        Lid::derive(
            CanonicalizationVersion::V1,
            &canonicalize(CanonicalizationVersion::V1, &a),
        )
    };

    let dek = make("dek");
    let kek = make("kek");
    let root = make("tenant-root");
    let signing = make("signing-key");

    assert_ne!(dek, kek);
    assert_ne!(dek, root);
    assert_ne!(dek, signing);
    assert_ne!(kek, root);
    assert_ne!(kek, signing);
    assert_ne!(root, signing);
}

// ────────────────────────────────────────────────────────────────────
// Sensitive<T> redaction
// ────────────────────────────────────────────────────────────────────

/// Sensitive<T> must never leak plaintext through Debug or Display,
/// but must allow controlled access via expose().
#[test]
fn sensitive_redaction_e2e() {
    let secret_key = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let wrapped = Sensitive::new(secret_key.clone());

    let debug = format!("{wrapped:?}");
    let display = format!("{wrapped}");

    assert_eq!(debug, "[REDACTED]");
    assert_eq!(display, "[REDACTED]");
    assert!(!debug.contains("222"));
    assert!(!debug.contains("DEAD"));

    assert_eq!(wrapped.expose(), &secret_key);

    let cloned = wrapped.clone();
    assert_eq!(cloned.expose(), wrapped.expose());

    let v = wrapped.into_inner();
    assert_eq!(v, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

// ────────────────────────────────────────────────────────────────────
// Key state machine
// ────────────────────────────────────────────────────────────────────

/// Walk the full happy-path lifecycle:
///   creating → enabled → disabled → enabled → pending_deletion → destroyed
#[test]
fn key_state_machine_full_lifecycle() {
    assert!(KeyState::Creating.can_transition_to(KeyState::Enabled));
    assert!(KeyState::Enabled.can_transition_to(KeyState::Disabled));
    assert!(KeyState::Disabled.can_transition_to(KeyState::Enabled));
    assert!(KeyState::Enabled.can_transition_to(KeyState::PendingDeletion));
    assert!(KeyState::PendingDeletion.can_transition_to(KeyState::Destroyed));
    assert!(KeyState::Destroyed.valid_transitions().is_empty());
}

/// Cancel deletion: pending_deletion → disabled → enabled
#[test]
fn key_state_machine_cancel_deletion() {
    assert!(KeyState::PendingDeletion.can_transition_to(KeyState::Disabled));
    assert!(KeyState::Disabled.can_transition_to(KeyState::Enabled));
}

/// Encrypt/decrypt permissions track the spec:
///   encrypt: enabled only; decrypt: enabled + disabled (data recovery)
#[test]
fn key_state_operation_permissions() {
    for state in &[
        KeyState::Creating,
        KeyState::Disabled,
        KeyState::PendingDeletion,
        KeyState::Destroyed,
    ] {
        assert!(!state.permits_encrypt(), "{state:?} should not permit encrypt");
    }
    assert!(KeyState::Enabled.permits_encrypt());

    assert!(KeyState::Enabled.permits_decrypt());
    assert!(KeyState::Disabled.permits_decrypt());
    assert!(!KeyState::PendingDeletion.permits_decrypt());
    assert!(!KeyState::Destroyed.permits_decrypt());
}

/// KeyRecord transitions bump version and update timestamp.
#[test]
fn key_record_transition_bumps_version() {
    let mut record = make_test_record(KeyState::Enabled);
    let v0 = record.version;
    let t0 = record.updated_at;

    std::thread::sleep(std::time::Duration::from_millis(10));
    record.transition_to(KeyState::Disabled).unwrap();

    assert_eq!(record.state, KeyState::Disabled);
    assert_eq!(record.version, v0 + 1);
    assert!(record.updated_at >= t0);
}

/// Invalid transitions return Err and leave state unchanged.
#[test]
fn key_record_invalid_transition_is_noop() {
    let mut record = make_test_record(KeyState::Creating);
    let snap = record.version;
    assert!(record.transition_to(KeyState::Destroyed).is_err());
    assert_eq!(record.state, KeyState::Creating);
    assert_eq!(record.version, snap);
}

/// KeyState round-trips through JSON.
#[test]
fn key_state_serde_round_trip() {
    for state in &[
        KeyState::Creating,
        KeyState::Enabled,
        KeyState::Disabled,
        KeyState::PendingDeletion,
        KeyState::Destroyed,
    ] {
        let json = serde_json::to_string(state).unwrap();
        let parsed: KeyState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, parsed);
    }
}

// ────────────────────────────────────────────────────────────────────
// Tags model
// ────────────────────────────────────────────────────────────────────

/// Identity tags are derived from the attribute set and are immutable.
/// User tags are freely mutable. The two namespaces do not collide.
#[test]
fn tags_model_e2e() {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("acme".into()));
    attrs.insert("kind", AttributeValue::String("dek".into()));
    attrs.insert("priority", AttributeValue::I64(7));

    let identity = IdentityTags::from_attribute_set(&attrs);
    assert_eq!(identity.get("tenant"), Some("acme"));
    assert_eq!(identity.get("kind"), Some("dek"));
    assert_eq!(identity.get("priority"), Some("7"));
    assert_eq!(identity.len(), 3);

    // User tags: independent CRUD.
    let mut user = UserTags::new();
    user.set("env", "production");
    user.set("team", "platform");
    assert_eq!(user.get("env"), Some("production"));
    assert_eq!(user.len(), 2);

    user.set("env", "staging");
    assert_eq!(user.get("env"), Some("staging"));

    user.remove("team");
    assert_eq!(user.len(), 1);

    // Mutating an identity tag key via the tag API is an error.
    let err = validate_tag_mutation(&identity, "tenant");
    assert!(matches!(
        err,
        Err(KeyRackError::ImmutableTag { ref key }) if key == "tenant"
    ));

    // Non-identity keys are fine.
    assert!(validate_tag_mutation(&identity, "env").is_ok());
    assert!(validate_tag_mutation(&identity, "some-custom-tag").is_ok());
}

/// Both tag types round-trip through JSON (serde boundary).
#[test]
fn tags_serde_round_trip() {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("acme".into()));
    let identity = IdentityTags::from_attribute_set(&attrs);
    let json = serde_json::to_string(&identity).unwrap();
    let parsed: IdentityTags = serde_json::from_str(&json).unwrap();
    assert_eq!(identity, parsed);

    let mut user = UserTags::new();
    user.set("env", "prod");
    let json = serde_json::to_string(&user).unwrap();
    let parsed: UserTags = serde_json::from_str(&json).unwrap();
    assert_eq!(user, parsed);
}

// ────────────────────────────────────────────────────────────────────
// Integrated: full key lifecycle with tags
// ────────────────────────────────────────────────────────────────────

/// Full lifecycle: create attributes → derive LID → create KeyRecord →
/// walk through state transitions → verify tag immutability along the way.
#[test]
fn full_key_lifecycle_with_tags() {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("globex".into()));
    attrs.insert("kind", AttributeValue::String("dek".into()));

    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(CanonicalizationVersion::V1, &form);
    let identity_tags = IdentityTags::from_attribute_set(&attrs);
    let mut user_tags = UserTags::new();
    user_tags.set("environment", "dev");

    let mut record = KeyRecord {
        lid: lid.clone(),
        canonicalization_version: CanonicalizationVersion::V1,
        parent_lid: None,
        version: 1,
        state: KeyState::Creating,
        key_usage: KeyUsage::EncryptDecrypt,
        key_spec: KeySpec::Aes256,
        provider_class: ProviderClass::Software,
        identity_tags: identity_tags.clone(),
        user_tags,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        scheduled_deletion_at: None,
        description: "E2E test key".into(),
    };

    // creating → enabled
    assert!(record.transition_to(KeyState::Enabled).is_ok());
    assert!(record.state.permits_encrypt());
    assert!(record.state.permits_decrypt());

    // Add user tags while enabled.
    assert!(validate_tag_mutation(&record.identity_tags, "cost-center").is_ok());
    record.user_tags.set("cost-center", "engineering");

    // Cannot mutate identity tags.
    assert!(validate_tag_mutation(&record.identity_tags, "tenant").is_err());
    assert!(validate_tag_mutation(&record.identity_tags, "kind").is_err());

    // enabled → disabled
    assert!(record.transition_to(KeyState::Disabled).is_ok());
    assert!(!record.state.permits_encrypt());
    assert!(record.state.permits_decrypt()); // data recovery

    // disabled → pending_deletion
    assert!(record.transition_to(KeyState::PendingDeletion).is_ok());
    assert!(!record.state.permits_encrypt());
    assert!(!record.state.permits_decrypt());

    // pending_deletion → destroyed (terminal)
    assert!(record.transition_to(KeyState::Destroyed).is_ok());
    assert!(record.state.valid_transitions().is_empty());

    // LID is stable throughout.
    assert_eq!(record.lid, lid);
    assert_eq!(record.identity_tags.get("tenant"), Some("globex"));
}

// ────────────────────────────────────────────────────────────────────
// Test helpers
// ────────────────────────────────────────────────────────────────────

fn make_test_record(state: KeyState) -> KeyRecord {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("test-tenant".into()));
    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(CanonicalizationVersion::V1, &form);

    KeyRecord {
        lid,
        canonicalization_version: CanonicalizationVersion::V1,
        parent_lid: None,
        version: 1,
        state,
        key_usage: KeyUsage::EncryptDecrypt,
        key_spec: KeySpec::Aes256,
        provider_class: ProviderClass::Software,
        identity_tags: IdentityTags::from_attribute_set(&attrs),
        user_tags: UserTags::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        scheduled_deletion_at: None,
        description: String::new(),
    }
}
