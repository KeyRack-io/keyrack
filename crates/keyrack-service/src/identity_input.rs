// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Preserve identity-map ambiguity until validation at the REST JSON boundary.

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// An identity-bearing REST object with validated, normalized string attributes.
///
/// Parsing into `Value` first would discard repeated object keys. Deserialize
/// `attributes` directly, preserving opaque provider selectors separately from
/// canonical identity values. A supplied namespace must be a string; omission
/// means no namespace, while `null` has no defined identity meaning. Other fields
/// retain their existing JSON representation.
#[derive(Debug)]
pub struct IdentityRequest(pub Value);

impl<'de> Deserialize<'de> for IdentityRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Attributes(BTreeMap<String, String>);

        impl<'de> Deserialize<'de> for Attributes {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct AttributesVisitor;

                impl<'de> Visitor<'de> for AttributesVisitor {
                    type Value = Attributes;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("string attributes with unique NFC names")
                    }

                    fn visit_map<M: MapAccess<'de>>(
                        self,
                        mut input: M,
                    ) -> Result<Self::Value, M::Error> {
                        let mut attributes = BTreeMap::new();
                        while let Some((key, value)) = input.next_entry::<String, String>()? {
                            let key = keyrack_core::canon::normalize_text(&key);
                            if attributes.insert(key.clone(), value).is_some() {
                                return Err(M::Error::custom(
                                    keyrack_core::canon::CanonicalizationError::DuplicateName(key),
                                ));
                            }
                        }
                        // This reserved field selects an issuer-defined provider ID;
                        // it is removed by each handler before LID derivation.
                        let provider = attributes.remove("keyrack.provider");
                        let mut attributes = keyrack_core::attr::normalize_flat(&attributes)
                            .map_err(M::Error::custom)?;
                        if let Some(provider) = provider {
                            attributes.insert("keyrack.provider".into(), provider);
                        }
                        Ok(Attributes(attributes))
                    }
                }

                deserializer.deserialize_map(AttributesVisitor)
            }
        }

        struct RequestVisitor;

        impl<'de> Visitor<'de> for RequestVisitor {
            type Value = IdentityRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with unique fields and string identity attributes")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
                let mut body = Map::new();
                while let Some(key) = input.next_key::<String>()? {
                    if body.contains_key(&key) {
                        return Err(M::Error::custom(format!("duplicate request field: {key}")));
                    }
                    let value = if key == "attributes" {
                        let Attributes(attributes) = input.next_value::<Attributes>()?;
                        Value::Object(
                            attributes
                                .into_iter()
                                .map(|(key, value)| (key, Value::String(value)))
                                .collect(),
                        )
                    } else if key == "namespace" {
                        Value::String(keyrack_core::canon::normalize_text(
                            &input.next_value::<String>()?,
                        ))
                    } else {
                        input.next_value::<Value>()?
                    };
                    body.insert(key, value);
                }
                Ok(IdentityRequest(Value::Object(body)))
            }
        }

        deserializer.deserialize_map(RequestVisitor)
    }
}
