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

use crate::canon::{normalize_text, CanonicalizationError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_IDENTITY_BYTES: usize = 16 * 1024 * 1024;
const MAX_ATTRIBUTE_DEPTH: usize = 64;

fn charge(budget: &mut usize, bytes: usize) -> Result<(), CanonicalizationError> {
    *budget = budget
        .checked_sub(bytes)
        .ok_or(CanonicalizationError::LimitExceeded)?;
    Ok(())
}

fn text(value: &str, budget: &mut usize) -> Result<String, CanonicalizationError> {
    if value.len() > MAX_IDENTITY_BYTES {
        return Err(CanonicalizationError::LimitExceeded);
    }
    let normalized = normalize_text(value);
    charge(budget, normalized.len() + 5)?;
    Ok(normalized)
}

/// Normalize before sorting/duplicate detection. Equal-valued duplicate names
/// are still ambiguous and rejected. The input map is never modified on error.
pub fn normalize_flat(
    map: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, CanonicalizationError> {
    let mut normalized = BTreeMap::new();
    let mut budget = MAX_IDENTITY_BYTES;
    for (key, value) in map {
        let key = text(key, &mut budget)?;
        if normalized.contains_key(&key) {
            return Err(CanonicalizationError::DuplicateName(key));
        }
        normalized.insert(key, text(value, &mut budget)?);
    }
    Ok(normalized)
}

/// Lossless typed normalization for canonical encoding, including nested records.
pub fn normalize_attributes(attrs: &AttributeSet) -> Result<AttributeSet, CanonicalizationError> {
    fn map(
        input: &BTreeMap<String, AttributeValue>,
        depth: usize,
        budget: &mut usize,
    ) -> Result<BTreeMap<String, AttributeValue>, CanonicalizationError> {
        if depth > MAX_ATTRIBUTE_DEPTH {
            return Err(CanonicalizationError::LimitExceeded);
        }
        let mut out = BTreeMap::new();
        for (key, value) in input {
            let key = text(key, budget)?;
            if out.contains_key(&key) {
                return Err(CanonicalizationError::DuplicateName(key));
            }
            let value = match value {
                AttributeValue::String(s) => AttributeValue::String(text(s, budget)?),
                AttributeValue::I64(n) => {
                    charge(budget, 13)?;
                    AttributeValue::I64(*n)
                }
                AttributeValue::Bool(b) => {
                    charge(budget, 6)?;
                    AttributeValue::Bool(*b)
                }
                AttributeValue::ListOfString(items) => {
                    charge(budget, 9)?;
                    AttributeValue::ListOfString(
                        items
                            .iter()
                            .map(|s| text(s, budget))
                            .collect::<Result<_, _>>()?,
                    )
                }
                AttributeValue::Record(inner) => {
                    charge(budget, 5)?;
                    AttributeValue::Record(map(inner, depth + 1, budget)?)
                }
            };
            out.insert(key, value);
        }
        Ok(out)
    }
    let mut budget = MAX_IDENTITY_BYTES;
    Ok(AttributeSet(map(&attrs.0, 0, &mut budget)?))
}

/// Deserialize identity maps without allowing a map collector to discard duplicate
/// names first. Usable on request/config fields with `serde(deserialize_with)`.
pub fn deserialize_flat<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct FlatVisitor;
    impl<'de> serde::de::Visitor<'de> for FlatVisitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an identity map with unique NFC names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut input: M,
        ) -> Result<Self::Value, M::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = input.next_entry::<String, String>()? {
                let key = normalize_text(&key);
                if out.insert(key.clone(), normalize_text(&value)).is_some() {
                    return Err(serde::de::Error::custom(
                        CanonicalizationError::DuplicateName(key),
                    ));
                }
            }
            normalize_flat(&out).map_err(serde::de::Error::custom)
        }
    }
    deserializer.deserialize_map(FlatVisitor)
}

/// A single attribute value in an attribute set.
///
/// The type set mirrors `PDP_WIRE_FORMAT_REQS.md` R-Q11:
/// strings, integers, booleans, lists of strings, and records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    I64(i64),
    Bool(bool),
    ListOfString(Vec<String>),
    Record(BTreeMap<String, AttributeValue>),
}

impl<'de> Deserialize<'de> for AttributeValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Value {
            String(String),
            I64(i64),
            Bool(bool),
            List(Vec<String>),
            Record(AttributeSet),
        }
        Ok(match Value::deserialize(d)? {
            Value::String(s) => Self::String(normalize_text(&s)),
            Value::I64(n) => Self::I64(n),
            Value::Bool(b) => Self::Bool(b),
            Value::List(v) => Self::ListOfString(v.iter().map(|s| normalize_text(s)).collect()),
            Value::Record(v) => Self::Record(v.0),
        })
    }
}

/// An ordered map of attribute key-value pairs.
///
/// Uses `BTreeMap` for deterministic iteration order — canonicalization
/// depends on this. Keys are always UTF-8 strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttributeSet(pub BTreeMap<String, AttributeValue>);

impl<'de> Deserialize<'de> for AttributeSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> serde::de::Visitor<'de> for MapVisitor {
            type Value = AttributeSet;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique NFC attribute names")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut input: M,
            ) -> Result<Self::Value, M::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = input.next_entry::<String, AttributeValue>()? {
                    let key = normalize_text(&key);
                    if out.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(
                            CanonicalizationError::DuplicateName(key),
                        ));
                    }
                }
                normalize_attributes(&AttributeSet(out)).map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_map(MapVisitor)
    }
}

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
