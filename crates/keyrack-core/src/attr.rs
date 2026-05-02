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

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single attribute value in an attribute set.
///
/// The type set mirrors `PDP_WIRE_FORMAT_REQS.md` R-Q11:
/// strings, integers, booleans, lists of strings, and records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    I64(i64),
    Bool(bool),
    ListOfString(Vec<String>),
    Record(BTreeMap<String, AttributeValue>),
}

/// An ordered map of attribute key-value pairs.
///
/// Uses `BTreeMap` for deterministic iteration order — canonicalization
/// depends on this. Keys are always UTF-8 strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeSet(pub BTreeMap<String, AttributeValue>);

impl AttributeSet {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, key: impl Into<String>, value: AttributeValue) {
        self.0.insert(key.into(), value);
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&AttributeValue> {
        self.0.get(key)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &AttributeValue)> {
        self.0.iter()
    }
}

impl Default for AttributeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl From<BTreeMap<String, AttributeValue>> for AttributeSet {
    fn from(map: BTreeMap<String, AttributeValue>) -> Self {
        Self(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_set_insert_and_get() {
        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("acme".into()));
        attrs.insert("priority", AttributeValue::I64(42));
        attrs.insert("active", AttributeValue::Bool(true));

        assert_eq!(
            attrs.get("tenant"),
            Some(&AttributeValue::String("acme".into()))
        );
        assert_eq!(attrs.get("priority"), Some(&AttributeValue::I64(42)));
        assert_eq!(attrs.get("active"), Some(&AttributeValue::Bool(true)));
        assert_eq!(attrs.get("missing"), None);
        assert_eq!(attrs.len(), 3);
    }

    #[test]
    fn attribute_set_deterministic_order() {
        let mut a = AttributeSet::new();
        a.insert("z", AttributeValue::Bool(true));
        a.insert("a", AttributeValue::Bool(false));
        a.insert("m", AttributeValue::I64(0));

        let keys: Vec<&String> = a.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }

    #[test]
    fn attribute_value_list_of_string() {
        let v = AttributeValue::ListOfString(vec!["one".into(), "two".into()]);
        if let AttributeValue::ListOfString(items) = &v {
            assert_eq!(items.len(), 2);
        } else {
            panic!("expected ListOfString");
        }
    }

    #[test]
    fn attribute_value_nested_record() {
        let mut inner = BTreeMap::new();
        inner.insert("x".into(), AttributeValue::I64(1));
        let v = AttributeValue::Record(inner);
        if let AttributeValue::Record(map) = &v {
            assert_eq!(map.get("x"), Some(&AttributeValue::I64(1)));
        } else {
            panic!("expected Record");
        }
    }

    #[test]
    fn serde_round_trip() {
        let mut attrs = AttributeSet::new();
        attrs.insert("name", AttributeValue::String("test".into()));
        attrs.insert("count", AttributeValue::I64(7));
        attrs.insert("enabled", AttributeValue::Bool(false));
        attrs.insert(
            "tags",
            AttributeValue::ListOfString(vec!["a".into(), "b".into()]),
        );
        let mut rec = BTreeMap::new();
        rec.insert("nested_key".into(), AttributeValue::String("val".into()));
        attrs.insert("extra", AttributeValue::Record(rec));

        let json = serde_json::to_string(&attrs).unwrap();
        let roundtripped: AttributeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(attrs, roundtripped);
    }
}
