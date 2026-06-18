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

//! Tags model: identity tags vs. user tags.
//!
//! **Identity tags** are immutable, derived from the attribute set at key
//! creation. They appear in audit events and PDP requests only. They are
//! excluded from tenant-facing API responses (`KEYRACK_SPEC.md` §5.14,
//! invariant 9).
//!
//! **User tags** are mutable via `TagResource` / `UntagResource`. They
//! appear in API responses and are tenant-controllable.
//!
//! Both categories are visible to the PDP for authorization decisions.
//!
//! Attempts to mutate identity tags through the tag API return
//! `ImmutableTagError`.

use crate::attr::{AttributeSet, AttributeValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Identity tags derived from the attribute set at key creation.
///
/// Immutable after creation. Serialized as a separate field on `KeyRecord`
/// (not mixed with user tags). The serialization convention is a flat map
/// where complex attribute values are JSON-stringified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityTags(BTreeMap<String, String>);

impl IdentityTags {
    /// Derive identity tags from an attribute set.
    ///
    /// All attribute values are flattened to strings: `String` values are
    /// kept as-is, other types are JSON-serialized. This ensures identity
    /// tags are always simple key-value pairs suitable for inclusion in
    /// audit events and PDP requests.
    #[must_use]
    pub fn from_attribute_set(attrs: &AttributeSet) -> Self {
        let map = attrs
            .iter()
            .map(|(k, v)| {
                let s = match v {
                    AttributeValue::String(s) => s.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                };
                (k.clone(), s)
            })
            .collect();
        Self(map)
    }

    /// Construct directly from a string map (useful for tests and routing).
    #[must_use]
    pub fn from_map(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}

/// Mutable user tags set by operators / tenants.
///
/// Visible in API responses. Modifiable via `TagResource` / `UntagResource`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserTags(BTreeMap<String, String>);

impl UserTags {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    /// Remove a user tag. Returns the old value if the key existed.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}

impl Default for UserTags {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that enforces the identity/user tag boundary.
///
/// Given the identity tags on a key, validates that a `TagResource` or
/// `UntagResource` operation does not target an identity tag key.
pub fn validate_tag_mutation(
    identity_tags: &IdentityTags,
    tag_key: &str,
) -> std::result::Result<(), crate::error::KeyRackError> {
    if identity_tags.contains_key(tag_key) {
        Err(crate::error::KeyRackError::ImmutableTag {
            key: tag_key.to_string(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{AttributeSet, AttributeValue};
    use std::collections::BTreeMap;

    fn sample_attrs() -> AttributeSet {
        let mut attrs = AttributeSet::new();
        attrs.insert("tenant", AttributeValue::String("acme".into()));
        attrs.insert("kind", AttributeValue::String("dek".into()));
        attrs.insert("priority", AttributeValue::I64(1));
        attrs.insert("active", AttributeValue::Bool(true));
        attrs
    }

    #[test]
    fn identity_tags_from_attribute_set() {
        let attrs = sample_attrs();
        let tags = IdentityTags::from_attribute_set(&attrs);

        assert_eq!(tags.get("tenant"), Some("acme"));
        assert_eq!(tags.get("kind"), Some("dek"));
        assert_eq!(tags.get("priority"), Some("1"));
        assert_eq!(tags.get("active"), Some("true"));
        assert_eq!(tags.get("missing"), None);
        assert_eq!(tags.len(), 4);
    }

    #[test]
    fn identity_tags_complex_values() {
        let mut attrs = AttributeSet::new();
        attrs.insert(
            "tags",
            AttributeValue::ListOfString(vec!["a".into(), "b".into()]),
        );
        let mut rec = BTreeMap::new();
        rec.insert("x".into(), AttributeValue::I64(1));
        attrs.insert("extra", AttributeValue::Record(rec));

        let tags = IdentityTags::from_attribute_set(&attrs);
        assert!(tags.get("tags").unwrap().starts_with('['));
        assert!(tags.get("extra").unwrap().starts_with('{'));
    }

    #[test]
    fn user_tags_crud() {
        let mut tags = UserTags::new();
        assert!(tags.is_empty());

        tags.set("env", "production");
        tags.set("team", "platform");
        assert_eq!(tags.len(), 2);
        assert_eq!(tags.get("env"), Some("production"));

        tags.set("env", "staging");
        assert_eq!(tags.get("env"), Some("staging"));
        assert_eq!(tags.len(), 2);

        let old = tags.remove("team");
        assert_eq!(old, Some("platform".into()));
        assert_eq!(tags.len(), 1);
        assert!(!tags.contains_key("team"));
    }

    #[test]
    fn validate_tag_mutation_blocks_identity_keys() {
        let attrs = sample_attrs();
        let identity = IdentityTags::from_attribute_set(&attrs);

        let result = validate_tag_mutation(&identity, "tenant");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::KeyRackError::ImmutableTag { ref key } if key == "tenant")
        );
    }

    #[test]
    fn validate_tag_mutation_allows_non_identity_keys() {
        let attrs = sample_attrs();
        let identity = IdentityTags::from_attribute_set(&attrs);

        assert!(validate_tag_mutation(&identity, "env").is_ok());
        assert!(validate_tag_mutation(&identity, "team").is_ok());
        assert!(validate_tag_mutation(&identity, "custom-tag").is_ok());
    }

    #[test]
    fn serde_round_trip_identity() {
        let attrs = sample_attrs();
        let tags = IdentityTags::from_attribute_set(&attrs);
        let json = serde_json::to_string(&tags).unwrap();
        let parsed: IdentityTags = serde_json::from_str(&json).unwrap();
        assert_eq!(tags, parsed);
    }

    #[test]
    fn serde_round_trip_user() {
        let mut tags = UserTags::new();
        tags.set("env", "prod");
        tags.set("team", "kms");
        let json = serde_json::to_string(&tags).unwrap();
        let parsed: UserTags = serde_json::from_str(&json).unwrap();
        assert_eq!(tags, parsed);
    }
}
