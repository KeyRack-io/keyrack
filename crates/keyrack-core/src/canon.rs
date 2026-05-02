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

//! Attribute canonicalization.
//!
//! Produces a deterministic byte sequence from an [`AttributeSet`] under a
//! specific canonicalization version. The byte format is versioned so future
//! changes trigger the alias-based migration in `MIGRATION.md` rather than
//! silently invalidating existing LIDs.

use crate::attr::{AttributeSet, AttributeValue};
use unicode_normalization::UnicodeNormalization;

/// Canonicalization version tag. Stored in every key record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum CanonicalizationVersion {
    V1 = 1,
}

impl CanonicalizationVersion {
    #[must_use]
    pub fn as_le_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

/// The deterministic byte representation of an attribute set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalForm(Vec<u8>);

impl CanonicalForm {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

// Tag bytes for the TLV encoding.
const TAG_STRING: u8 = 0x01;
const TAG_I64: u8 = 0x02;
const TAG_BOOL: u8 = 0x03;
const TAG_LIST_OF_STRING: u8 = 0x04;
const TAG_RECORD: u8 = 0x05;

/// Canonicalize an attribute set under the given version.
pub fn canonicalize(
    version: CanonicalizationVersion,
    attrs: &AttributeSet,
) -> CanonicalForm {
    match version {
        CanonicalizationVersion::V1 => canonicalize_v1(attrs),
    }
}

/// V1 canonicalization.
///
/// Encoding: for each entry in the `BTreeMap` (which iterates in sorted key
/// order):
///
/// 1. Encode the key as a NFC-normalised UTF-8 string (`TAG_STRING` + u32 LE
///    length + bytes).
/// 2. Encode the value per its type tag.
///
/// Values are TLV-encoded:
/// - `TAG` (1 byte) + `LENGTH` (u32 LE, byte count of the payload) + payload.
/// - Strings: NFC-normalised UTF-8 bytes.
/// - I64: 8 bytes little-endian.
/// - Bool: 1 byte (`0x01` true, `0x00` false).
/// - `ListOfString`: u32 LE element count, then each element as (u32 LE length
///   + NFC UTF-8 bytes). No per-element tag — the list is homogeneous.
/// - Record: recursive — canonicalize the inner `BTreeMap` as a nested
///   attribute set (same key+value encoding, sorted).
fn canonicalize_v1(attrs: &AttributeSet) -> CanonicalForm {
    let mut buf = Vec::new();
    encode_map(&mut buf, &attrs.0);
    CanonicalForm(buf)
}

fn encode_map(buf: &mut Vec<u8>, map: &std::collections::BTreeMap<String, AttributeValue>) {
    for (key, value) in map {
        encode_string_raw(buf, key);
        encode_value(buf, value);
    }
}

#[allow(clippy::cast_possible_truncation)] // attribute values bounded well under 4 GB
fn encode_string_raw(buf: &mut Vec<u8>, s: &str) {
    let normalised: String = s.nfc().collect();
    let bytes = normalised.as_bytes();
    buf.push(TAG_STRING);
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[allow(clippy::cast_possible_truncation)] // attribute values bounded well under 4 GB
fn encode_value(buf: &mut Vec<u8>, value: &AttributeValue) {
    match value {
        AttributeValue::String(s) => {
            encode_string_raw(buf, s);
        }
        AttributeValue::I64(n) => {
            buf.push(TAG_I64);
            buf.extend_from_slice(&8_u32.to_le_bytes());
            buf.extend_from_slice(&n.to_le_bytes());
        }
        AttributeValue::Bool(b) => {
            buf.push(TAG_BOOL);
            buf.extend_from_slice(&1_u32.to_le_bytes());
            buf.push(u8::from(*b));
        }
        AttributeValue::ListOfString(list) => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for item in list {
                let normalised: String = item.nfc().collect();
                let bytes = normalised.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
            }
            buf.push(TAG_LIST_OF_STRING);
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        AttributeValue::Record(inner) => {
            let mut payload = Vec::new();
            encode_map(&mut payload, inner);
            buf.push(TAG_RECORD);
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AttributeSet, AttributeValue};
    use std::collections::BTreeMap;

    #[test]
    fn empty_attribute_set_produces_empty_bytes() {
        let attrs = AttributeSet::new();
        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        assert!(form.bytes().is_empty());
    }

    #[test]
    fn deterministic_across_calls() {
        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("acme".into()));
        attrs.insert("priority", AttributeValue::I64(42));

        let a = canonicalize(CanonicalizationVersion::V1, &attrs);
        let b = canonicalize(CanonicalizationVersion::V1, &attrs);
        assert_eq!(a, b);
    }

    #[test]
    fn key_order_does_not_matter() {
        let mut a = AttributeSet::new();
        a.insert("z", AttributeValue::Bool(true));
        a.insert("a", AttributeValue::I64(1));

        let mut b = AttributeSet::new();
        b.insert("a", AttributeValue::I64(1));
        b.insert("z", AttributeValue::Bool(true));

        assert_eq!(
            canonicalize(CanonicalizationVersion::V1, &a),
            canonicalize(CanonicalizationVersion::V1, &b),
        );
    }

    #[test]
    fn nfc_normalisation() {
        // U+00E9 (é precomposed) vs U+0065 U+0301 (e + combining acute)
        let mut a = AttributeSet::new();
        a.insert("name", AttributeValue::String("\u{00e9}".into()));

        let mut b = AttributeSet::new();
        b.insert("name", AttributeValue::String("e\u{0301}".into()));

        assert_eq!(
            canonicalize(CanonicalizationVersion::V1, &a),
            canonicalize(CanonicalizationVersion::V1, &b),
        );
    }

    #[test]
    fn different_values_produce_different_forms() {
        let mut a = AttributeSet::new();
        a.insert("x", AttributeValue::I64(1));

        let mut b = AttributeSet::new();
        b.insert("x", AttributeValue::I64(2));

        assert_ne!(
            canonicalize(CanonicalizationVersion::V1, &a),
            canonicalize(CanonicalizationVersion::V1, &b),
        );
    }

    #[test]
    fn different_types_produce_different_forms() {
        let mut a = AttributeSet::new();
        a.insert("x", AttributeValue::I64(1));

        let mut b = AttributeSet::new();
        b.insert("x", AttributeValue::String("1".into()));

        assert_ne!(
            canonicalize(CanonicalizationVersion::V1, &a),
            canonicalize(CanonicalizationVersion::V1, &b),
        );
    }

    #[test]
    fn nested_record() {
        let mut inner = BTreeMap::new();
        inner.insert("level".into(), AttributeValue::I64(2));

        let mut attrs = AttributeSet::new();
        attrs.insert("outer", AttributeValue::Record(inner));

        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        assert!(!form.bytes().is_empty());

        let again = canonicalize(CanonicalizationVersion::V1, &attrs);
        assert_eq!(form, again);
    }

    #[test]
    fn list_of_string_encoding() {
        let mut attrs = AttributeSet::new();
        attrs.insert(
            "tags",
            AttributeValue::ListOfString(vec!["a".into(), "b".into(), "c".into()]),
        );

        let form = canonicalize(CanonicalizationVersion::V1, &attrs);
        assert!(!form.bytes().is_empty());

        let again = canonicalize(CanonicalizationVersion::V1, &attrs);
        assert_eq!(form, again);
    }

    #[test]
    fn integer_edge_cases() {
        for &val in &[i64::MIN, -1, 0, 1, i64::MAX] {
            let mut attrs = AttributeSet::new();
            attrs.insert("n", AttributeValue::I64(val));
            let form = canonicalize(CanonicalizationVersion::V1, &attrs);
            let again = canonicalize(CanonicalizationVersion::V1, &attrs);
            assert_eq!(form, again);
        }
    }

    #[test]
    fn bool_true_and_false_differ() {
        let mut a = AttributeSet::new();
        a.insert("flag", AttributeValue::Bool(true));

        let mut b = AttributeSet::new();
        b.insert("flag", AttributeValue::Bool(false));

        assert_ne!(
            canonicalize(CanonicalizationVersion::V1, &a),
            canonicalize(CanonicalizationVersion::V1, &b),
        );
    }

    #[test]
    fn version_le_bytes() {
        assert_eq!(CanonicalizationVersion::V1.as_le_bytes(), [1, 0, 0, 0]);
    }
}
