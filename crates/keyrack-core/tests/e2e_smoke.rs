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
//!   [x] Software provider encrypt/decrypt round-trip (AES-256-GCM)
//!   [x] Software provider sign/verify round-trip (Ed25519, ECDSA P-256, RSA)
//!   [x] InMemory provider parity
//!   [x] Ciphertext header encode/decode round-trip
//!   [x] Encryption context (AAD) hash determinism and binding
//!   [ ] Cascade-disable propagation                    (pending)
//!   [ ] Audit event emission                           (pending)

use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::encryption_context::{EncryptionContext, ZERO_CONTEXT_HASH};
use keyrack_core::error::KeyRackError;
use keyrack_core::header::{CiphertextHeader, HEADER_SIZE};
use keyrack_core::key::{
    KeyOrigin, KeyRecord, KeySpec, KeyState, KeyUsage, KeyVersionRecord, ProviderClass,
};
use keyrack_core::lid::Lid;
use keyrack_core::provider::inmem::InMemoryProvider;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::{CryptoProvider, SigningAlgorithm};
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
    let v0 = record.occ_version;
    let t0 = record.updated_at;

    std::thread::sleep(std::time::Duration::from_millis(10));
    record.transition_to(KeyState::Disabled).unwrap();

    assert_eq!(record.state, KeyState::Disabled);
    assert_eq!(record.occ_version, v0 + 1);
    assert!(record.updated_at >= t0);
}

/// Invalid transitions return Err and leave state unchanged.
#[test]
fn key_record_invalid_transition_is_noop() {
    let mut record = make_test_record(KeyState::Creating);
    let snap = record.occ_version;
    assert!(record.transition_to(KeyState::Destroyed).is_err());
    assert_eq!(record.state, KeyState::Creating);
    assert_eq!(record.occ_version, snap);
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
        occ_version: 1,
        current_key_version: 1,
        state: KeyState::Creating,
        key_usage: KeyUsage::EncryptDecrypt,
        key_spec: KeySpec::Aes256,
        origin: KeyOrigin::KeyRack,
        provider_class: ProviderClass::Software,
        identity_tags: identity_tags.clone(),
        user_tags,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        scheduled_deletion_at: None,
        description: "E2E test key".into(),
        key_versions: vec![KeyVersionRecord {
            version_number: 1,
            key_handle: keyrack_core::provider::KeyHandle {
                key_id: "test".into(),
                key_spec: KeySpec::Aes256,
            },
            created_at: chrono::Utc::now(),
            is_primary: true,
        }],
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
// Provider: encrypt/decrypt round-trips
// ────────────────────────────────────────────────────────────────────

/// AES-256-GCM encrypt → decrypt round-trip with AAD binding.
#[tokio::test]
async fn provider_aes256_gcm_round_trip() {
    let provider = SoftwareProvider::new();
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

    let plaintext = b"volume DEK material - 32 bytes!!";
    let aad = b"tenant=acme,lid=lid_abc123";

    let ct = provider.encrypt(&handle, plaintext, aad).await.unwrap();
    assert_ne!(ct.ciphertext, plaintext, "ciphertext must differ from plaintext");

    let pt = provider.decrypt(&handle, &ct.ciphertext, aad).await.unwrap();
    assert_eq!(pt.expose().as_slice(), plaintext);
}

/// AAD mismatch must fail decryption (integrity guarantee).
#[tokio::test]
async fn provider_aes256_gcm_aad_mismatch_fails() {
    let provider = SoftwareProvider::new();
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

    let ct = provider.encrypt(&handle, b"secret", b"context-a").await.unwrap();
    let result = provider.decrypt(&handle, &ct.ciphertext, b"context-b").await;
    assert!(result.is_err(), "wrong AAD must fail decryption");
}

/// Each V1 signing algorithm: keygen → sign → verify → tampered-verify-fails.
#[tokio::test]
async fn provider_sign_verify_all_v1_algorithms() {
    let provider = SoftwareProvider::new();
    let message = b"backup manifest hash: sha256:abc123...";

    let specs_and_algos = [
        (KeySpec::Ed25519, SigningAlgorithm::Ed25519),
        (KeySpec::EcdsaP256Sha256, SigningAlgorithm::EcdsaP256Sha256),
        (
            KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
            SigningAlgorithm::RsaPkcs1v15Sha256,
        ),
    ];

    for (spec, algo) in &specs_and_algos {
        let handle = provider.generate_key(spec).await.unwrap();

        let sig = provider.sign(&handle, *algo, message).await.unwrap();
        assert!(!sig.is_empty(), "{algo:?} signature must be non-empty");

        let valid = provider.verify(&handle, *algo, message, &sig).await.unwrap();
        assert!(valid, "{algo:?} valid signature must verify");

        let invalid = provider
            .verify(&handle, *algo, b"tampered message", &sig)
            .await
            .unwrap();
        assert!(!invalid, "{algo:?} tampered message must fail verification");
    }
}

/// InMemoryProvider produces the same results as SoftwareProvider.
#[tokio::test]
async fn provider_inmem_parity() {
    let provider = InMemoryProvider::new();
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

    let ct = provider.encrypt(&handle, b"parity test", b"aad").await.unwrap();
    let pt = provider.decrypt(&handle, &ct.ciphertext, b"aad").await.unwrap();
    assert_eq!(pt.expose().as_slice(), b"parity test");

    let sign_handle = provider.generate_key(&KeySpec::Ed25519).await.unwrap();
    let sig = provider
        .sign(&sign_handle, SigningAlgorithm::Ed25519, b"msg")
        .await
        .unwrap();
    assert!(provider
        .verify(&sign_handle, SigningAlgorithm::Ed25519, b"msg", &sig)
        .await
        .unwrap());
}

/// generate_random produces the requested length, and two calls differ.
#[tokio::test]
async fn provider_generate_random() {
    let provider = SoftwareProvider::new();
    let a = provider.generate_random(32).await.unwrap();
    let b = provider.generate_random(32).await.unwrap();

    assert_eq!(a.expose().len(), 32);
    assert_ne!(a.expose(), b.expose(), "two random calls must differ");
}

/// Destroyed keys cannot be used.
#[tokio::test]
async fn provider_destroy_prevents_use() {
    let provider = SoftwareProvider::new();
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
    provider.destroy_key(&handle).await.unwrap();

    assert!(provider.encrypt(&handle, b"test", b"").await.is_err());
}

// ────────────────────────────────────────────────────────────────────
// Ciphertext header + encryption context
// ────────────────────────────────────────────────────────────────────

/// Full pipeline: derive LID → build encryption context → create header
/// → encode → decode → verify all fields survive the round-trip.
#[test]
fn ciphertext_header_round_trip() {
    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("acme".into()));
    attrs.insert("kind", AttributeValue::String("dek".into()));
    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(CanonicalizationVersion::V1, &form);

    let mut ctx = EncryptionContext::new();
    ctx.insert("volume_id", "vol-123");
    ctx.insert("tenant", "acme");
    let ctx_hash = ctx.hash();

    let header = CiphertextHeader::new(lid.clone(), 7, ctx_hash);
    let encoded = header.encode();
    assert_eq!(encoded.len(), HEADER_SIZE);

    let decoded = CiphertextHeader::decode(&encoded).unwrap();
    assert_eq!(decoded.lid, lid);
    assert_eq!(decoded.key_version, 7);
    assert_eq!(decoded.encryption_context_hash, ctx_hash);
    assert!(decoded.has_encryption_context());
}

/// Header without encryption context uses the zero sentinel.
#[test]
fn ciphertext_header_no_context() {
    let lid = {
        let mut attrs = AttributeSet::new();
        attrs.insert("t", AttributeValue::String("x".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        Lid::derive(CanonicalizationVersion::V1, &form)
    };

    let header = CiphertextHeader::new(lid, 1, ZERO_CONTEXT_HASH);
    assert!(!header.has_encryption_context());

    let decoded = CiphertextHeader::decode(&header.encode()).unwrap();
    assert!(!decoded.has_encryption_context());
    assert_eq!(decoded.encryption_context_hash, ZERO_CONTEXT_HASH);
}

/// wrap_payload / unwrap_payload: header + ciphertext survive the round-trip.
#[test]
fn ciphertext_header_wrap_unwrap_payload() {
    let lid = {
        let mut attrs = AttributeSet::new();
        attrs.insert("t", AttributeValue::String("x".into()));
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        Lid::derive(CanonicalizationVersion::V1, &form)
    };

    let header = CiphertextHeader::new(lid, 1, ZERO_CONTEXT_HASH);
    let payload = b"AES-GCM nonce || ciphertext || tag";

    let blob = header.wrap_payload(payload);
    let (decoded_header, decoded_payload) = CiphertextHeader::unwrap_payload(&blob).unwrap();

    assert_eq!(decoded_header, header);
    assert_eq!(decoded_payload, payload);
}

/// Encryption context hash is deterministic regardless of insertion order.
#[test]
fn encryption_context_hash_determinism() {
    let mut a = EncryptionContext::new();
    a.insert("z_key", "z_val");
    a.insert("a_key", "a_val");

    let mut b = EncryptionContext::new();
    b.insert("a_key", "a_val");
    b.insert("z_key", "z_val");

    assert_eq!(a.hash(), b.hash());
    assert_eq!(a.to_aad_bytes(), b.to_aad_bytes());
}

/// Different encryption contexts produce different hashes (collision check).
#[test]
fn encryption_context_different_values_different_hash() {
    let mut a = EncryptionContext::new();
    a.insert("tenant", "acme");

    let mut b = EncryptionContext::new();
    b.insert("tenant", "globex");

    assert_ne!(a.hash(), b.hash());
}

/// Integrated test: encrypt with AAD from EncryptionContext, wrap in
/// header, unwrap, verify context hash, decrypt with same AAD.
#[tokio::test]
async fn integrated_encrypt_with_header_and_context() {
    let provider = SoftwareProvider::new();
    let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();

    let mut attrs = AttributeSet::new();
    attrs.insert("tenant", AttributeValue::String("acme".into()));
    let form = canonicalize(CanonicalizationVersion::V1, &attrs);
    let lid = Lid::derive(CanonicalizationVersion::V1, &form);

    let mut ctx = EncryptionContext::new();
    ctx.insert("volume_id", "vol-456");
    let aad = ctx.to_aad_bytes();
    let ctx_hash = ctx.hash();

    let plaintext = b"secret volume DEK";
    let ct = provider.encrypt(&handle, plaintext, &aad).await.unwrap();

    let header = CiphertextHeader::new(lid.clone(), 1, ctx_hash);
    let blob = header.wrap_payload(&ct.ciphertext);

    // Simulate storage → retrieval → decrypt.
    let (recovered_header, recovered_ct) = CiphertextHeader::unwrap_payload(&blob).unwrap();
    assert_eq!(recovered_header.lid, lid);
    assert_eq!(recovered_header.encryption_context_hash, ctx_hash);

    // Verify context matches before decrypting.
    let mut ctx_at_decrypt = EncryptionContext::new();
    ctx_at_decrypt.insert("volume_id", "vol-456");
    assert_eq!(ctx_at_decrypt.hash(), recovered_header.encryption_context_hash);

    let pt = provider
        .decrypt(&handle, recovered_ct, &ctx_at_decrypt.to_aad_bytes())
        .await
        .unwrap();
    assert_eq!(pt.expose().as_slice(), plaintext);
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
            key_handle: keyrack_core::provider::KeyHandle {
                key_id: "test".into(),
                key_spec: KeySpec::Aes256,
            },
            created_at: chrono::Utc::now(),
            is_primary: true,
        }],
    }
}
