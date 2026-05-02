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
//!   [ ] Ciphertext header encode/decode round-trip     (pending)
//!   [ ] Software provider encrypt/decrypt round-trip   (pending)
//!   [ ] Key state machine transitions                  (pending)
//!   [ ] Cascade-disable propagation                    (pending)
//!   [ ] Audit event emission                           (pending)

use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::lid::Lid;
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
