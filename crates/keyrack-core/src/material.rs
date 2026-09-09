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

//! Exclusive durable material descriptions and their compatibility codec.
//!
//! A wrapped description contains a bounded opaque storage reference, not key
//! bytes, a provider object handle, or an executable lease. Structural validity
//! establishes neither authenticated context nor freshness, custody or usability.
//! Provider and service lifecycle enforcement remain separate requirements.
//!
//! Resident versions retain their legacy flat JSON shape. Wrapped versions use a
//! tagged, versioned `material` object and omit the old required `key_handle`, so
//! old readers fail instead of interpreting wrapped material as resident. Unknown,
//! null or conflicting new fields never fall back to the legacy representation.
//! Duplicate fields are rejected while decoding raw JSON; decoding a prebuilt
//! JSON value cannot recover duplicates already discarded by its producer.

use crate::key::{KeySpec, KeyVersionRecord, ProviderRef};
use crate::lid::Lid;
use crate::provider::KeyHandle;
use crate::wrapping::{
    VersionedKeyId, WrappedKeyFormat, WrappingContextVersion, WrappingError, WrappingIdentifier,
};
use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Exactly one durable material representation for a key version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// An independently usable provider object. An absent binding retains legacy
    /// record/default-provider inheritance; new creation should bind explicitly.
    ProviderResident {
        key_handle: KeyHandle,
        provider_ref: Option<ProviderRef>,
    },
    /// Metadata only: no independently operable resident handle is represented.
    ParentWrapped(ParentWrappedMaterial),
}

/// Structurally validated reference to parent-wrapped material.
///
/// This descriptor does not select an authenticated wrapping construction or
/// verify the referenced object. It deliberately omits the child LID/spec:
/// a future consuming profile must authenticate and validate the enclosing key
/// and version alongside these bindings before any operation is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentWrappedMaterial {
    provider_ref: ProviderRef,
    security_domain: WrappingIdentifier,
    parent: VersionedKeyId,
    wrapping_context_version: WrappingContextVersion,
    key_format: WrappedKeyFormat,
    mechanism: WrappingIdentifier,
    wrapped_material_ref: WrappingIdentifier,
}

impl ParentWrappedMaterial {
    /// Validate bounded references and exact parent identity, not cryptography.
    /// Names are opaque identifiers; they are not paths to read or URLs to fetch.
    pub fn new(
        provider_ref: ProviderRef,
        security_domain: WrappingIdentifier,
        parent: VersionedKeyId,
        wrapping_context_version: WrappingContextVersion,
        key_format: WrappedKeyFormat,
        mechanism: WrappingIdentifier,
        wrapped_material_ref: WrappingIdentifier,
    ) -> Result<Self, WrappingError> {
        // ProviderRef itself permits arbitrary strings; the new persisted
        // binding must meet the same bound as all other wrapping identifiers.
        WrappingIdentifier::new(provider_ref.as_str())?;
        Ok(Self {
            provider_ref,
            security_domain,
            parent,
            wrapping_context_version,
            key_format,
            mechanism,
            wrapped_material_ref,
        })
    }

    #[must_use]
    pub fn provider_ref(&self) -> &ProviderRef {
        &self.provider_ref
    }

    #[must_use]
    pub fn security_domain(&self) -> &WrappingIdentifier {
        &self.security_domain
    }

    #[must_use]
    pub fn parent(&self) -> VersionedKeyId {
        self.parent
    }

    #[must_use]
    pub fn wrapping_context_version(&self) -> WrappingContextVersion {
        self.wrapping_context_version
    }

    #[must_use]
    pub fn key_format(&self) -> &WrappedKeyFormat {
        &self.key_format
    }

    #[must_use]
    pub fn mechanism(&self) -> &WrappingIdentifier {
        &self.mechanism
    }

    #[must_use]
    pub fn wrapped_material_ref(&self) -> &WrappingIdentifier {
        &self.wrapped_material_ref
    }
}

// Presence is not Option: a present null material/handle is malformed, while a
// present null legacy provider_ref is valid but still conflicts with material.
#[derive(Default)]
enum Field<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionWire {
    version_number: u64,
    #[serde(default)]
    key_handle: Field<ResidentHandleWire>,
    #[serde(default)]
    provider_ref: Field<Option<ProviderRef>>,
    #[serde(default)]
    material: Field<WrappedWire>,
    created_at: DateTime<Utc>,
    is_primary: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentHandleWire {
    key_id: String,
    key_spec: KeySpec,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaterialKind {
    ParentWrapped,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FormatKind {
    RawSecret,
    Pkcs8Der,
    ProviderNative,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatWire {
    kind: FormatKind,
    #[serde(default)]
    name: Field<String>,
}

impl Serialize for FormatWire {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_struct(
            "WrappedKeyFormat",
            if matches!(self.name, Field::Missing) {
                1
            } else {
                2
            },
        )?;
        map.serialize_field("kind", &self.kind)?;
        if let Field::Present(name) = &self.name {
            map.serialize_field("name", name)?;
        }
        map.end()
    }
}

impl From<&WrappedKeyFormat> for FormatWire {
    fn from(format: &WrappedKeyFormat) -> Self {
        match format {
            WrappedKeyFormat::RawSecret => Self {
                kind: FormatKind::RawSecret,
                name: Field::Missing,
            },
            WrappedKeyFormat::Pkcs8Der => Self {
                kind: FormatKind::Pkcs8Der,
                name: Field::Missing,
            },
            WrappedKeyFormat::ProviderNative(name) => Self {
                kind: FormatKind::ProviderNative,
                name: Field::Present(name.as_str().to_owned()),
            },
        }
    }
}

impl TryFrom<FormatWire> for WrappedKeyFormat {
    type Error = WrappingError;

    fn try_from(format: FormatWire) -> Result<Self, Self::Error> {
        match (format.kind, format.name) {
            (FormatKind::RawSecret, Field::Missing) => Ok(Self::RawSecret),
            (FormatKind::Pkcs8Der, Field::Missing) => Ok(Self::Pkcs8Der),
            (FormatKind::ProviderNative, Field::Present(name)) => {
                Ok(Self::ProviderNative(WrappingIdentifier::new(name)?))
            }
            _ => Err(WrappingError::InvalidKeyFormat),
        }
    }
}

/// Persistence format version is separate from the wrapping-context version.
const MATERIAL_FORMAT_VERSION: u16 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedWire {
    kind: MaterialKind,
    format_version: u16,
    provider_ref: ProviderRef,
    security_domain: String,
    parent_lid: [u8; 32],
    parent_version: u64,
    wrapping_context_version: u16,
    wrapped_key_format: FormatWire,
    wrapping_mechanism: String,
    wrapped_material_ref: String,
}

impl From<&ParentWrappedMaterial> for WrappedWire {
    fn from(material: &ParentWrappedMaterial) -> Self {
        Self {
            kind: MaterialKind::ParentWrapped,
            format_version: MATERIAL_FORMAT_VERSION,
            provider_ref: material.provider_ref.clone(),
            security_domain: material.security_domain.as_str().to_owned(),
            parent_lid: *material.parent.lid.as_bytes(),
            parent_version: material.parent.version.get(),
            wrapping_context_version: match material.wrapping_context_version {
                WrappingContextVersion::V1 => 1,
            },
            wrapped_key_format: FormatWire::from(&material.key_format),
            wrapping_mechanism: material.mechanism.as_str().to_owned(),
            wrapped_material_ref: material.wrapped_material_ref.as_str().to_owned(),
        }
    }
}

impl Serialize for KeyVersionRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if matches!(self.material, KeyMaterial::ParentWrapped(_)) && self.version_number == 0 {
            return Err(serde::ser::Error::custom(WrappingError::ZeroKeyVersion));
        }
        let fields = if matches!(self.material, KeyMaterial::ProviderResident { .. }) {
            5
        } else {
            4
        };
        let mut map = serializer.serialize_struct("KeyVersionRecord", fields)?;
        map.serialize_field("version_number", &self.version_number)?;
        match &self.material {
            KeyMaterial::ProviderResident {
                key_handle,
                provider_ref,
            } => {
                map.serialize_field("key_handle", key_handle)?;
                map.serialize_field("provider_ref", provider_ref)?;
            }
            KeyMaterial::ParentWrapped(material) => {
                map.serialize_field("material", &WrappedWire::from(material))?;
            }
        }
        map.serialize_field("created_at", &self.created_at)?;
        map.serialize_field("is_primary", &self.is_primary)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for KeyVersionRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = VersionWire::deserialize(deserializer)?;
        let material = match wire.material {
            Field::Missing => {
                let Field::Present(handle) = wire.key_handle else {
                    return Err(serde::de::Error::missing_field("key_handle"));
                };
                KeyMaterial::ProviderResident {
                    key_handle: KeyHandle {
                        key_id: handle.key_id,
                        key_spec: handle.key_spec,
                    },
                    provider_ref: match wire.provider_ref {
                        Field::Missing => None,
                        Field::Present(binding) => binding,
                    },
                }
            }
            Field::Present(material) => {
                if !matches!(wire.key_handle, Field::Missing)
                    || !matches!(wire.provider_ref, Field::Missing)
                {
                    return Err(serde::de::Error::custom(
                        "material conflicts with legacy key_handle/provider_ref fields",
                    ));
                }
                if material.format_version != MATERIAL_FORMAT_VERSION {
                    return Err(serde::de::Error::custom(
                        "unsupported material format version",
                    ));
                }
                if wire.version_number == 0 {
                    return Err(serde::de::Error::custom(WrappingError::ZeroKeyVersion));
                }
                let wrapped = ParentWrappedMaterial::new(
                    material.provider_ref,
                    WrappingIdentifier::new(material.security_domain)
                        .map_err(serde::de::Error::custom)?,
                    VersionedKeyId::new(
                        Lid::from_bytes(material.parent_lid),
                        material.parent_version,
                    )
                    .map_err(serde::de::Error::custom)?,
                    WrappingContextVersion::try_from(material.wrapping_context_version)
                        .map_err(serde::de::Error::custom)?,
                    WrappedKeyFormat::try_from(material.wrapped_key_format)
                        .map_err(serde::de::Error::custom)?,
                    WrappingIdentifier::new(material.wrapping_mechanism)
                        .map_err(serde::de::Error::custom)?,
                    WrappingIdentifier::new(material.wrapped_material_ref)
                        .map_err(serde::de::Error::custom)?,
                )
                .map_err(serde::de::Error::custom)?;
                KeyMaterial::ParentWrapped(wrapped)
            }
        };
        Ok(Self {
            version_number: wire.version_number,
            material,
            created_at: wire.created_at,
            is_primary: wire.is_primary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyRecord, KeyState};
    use crate::wrapping::MAX_WRAPPING_IDENTIFIER_BYTES;
    use proptest::prelude::*;
    use serde_json::{json, Value};

    const LEGACY: &str = r#"{"version_number":7,"key_handle":{"key_id":"legacy-object","key_spec":"AES256"},"provider_ref":"provider-a","created_at":"2026-09-05T12:00:00Z","is_primary":false}"#;

    // Frozen pre-material shape: unknown new fields were ignored, but a handle
    // was mandatory. Keep this independent of the current KeyVersionRecord.
    #[derive(Deserialize)]
    struct OldVersion {
        version_number: u64,
        key_handle: KeyHandle,
        #[serde(default)]
        provider_ref: Option<ProviderRef>,
        created_at: DateTime<Utc>,
        is_primary: bool,
    }

    fn identifier(value: &str) -> WrappingIdentifier {
        WrappingIdentifier::new(value).unwrap()
    }

    fn wrapped() -> KeyVersionRecord {
        KeyVersionRecord {
            version_number: 2,
            material: KeyMaterial::ParentWrapped(
                ParentWrappedMaterial::new(
                    ProviderRef::new("provider-b"),
                    identifier("domain:one"),
                    VersionedKeyId::new(Lid::from_bytes([1; 32]), 3).unwrap(),
                    WrappingContextVersion::V1,
                    WrappedKeyFormat::RawSecret,
                    identifier("unselected-profile"),
                    identifier("opaque:wrapped-ref"),
                )
                .unwrap(),
            ),
            created_at: "2026-09-05T12:00:00Z".parse().unwrap(),
            is_primary: true,
        }
    }

    fn wrapped_json() -> Value {
        serde_json::to_value(wrapped()).unwrap()
    }

    fn assert_invalid(value: Value) {
        let description = value.to_string();
        assert!(
            serde_json::from_value::<KeyVersionRecord>(value).is_err(),
            "accepted {description}"
        );
    }

    #[test]
    fn frozen_legacy_round_trip_and_old_reader_compatibility() {
        let version: KeyVersionRecord = serde_json::from_str(LEGACY).unwrap();
        assert!(matches!(
            version.material,
            KeyMaterial::ProviderResident { .. }
        ));
        assert_eq!(version.resident_handle().unwrap().key_id, "legacy-object");
        assert_eq!(version.provider_ref().unwrap().as_str(), "provider-a");
        let json = serde_json::to_string(&version).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap(),
            serde_json::from_str::<Value>(LEGACY).unwrap()
        );
        let old: OldVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(old.version_number, version.version_number);
        assert_eq!(old.key_handle, *version.resident_handle().unwrap());
        assert_eq!(old.provider_ref.as_ref(), version.provider_ref());
        assert_eq!(old.created_at, version.created_at);
        assert_eq!(old.is_primary, version.is_primary);

        let mut without_binding: Value = serde_json::from_str(LEGACY).unwrap();
        without_binding
            .as_object_mut()
            .unwrap()
            .remove("provider_ref");
        let mut version: KeyVersionRecord = serde_json::from_value(without_binding).unwrap();
        assert!(version.provider_ref().is_none());
        version.resident_handle_mut().unwrap().key_id = "replacement".into();
        let json = serde_json::to_string(&version).unwrap();
        let old: OldVersion = serde_json::from_str(&json).unwrap();
        assert!(old.provider_ref.is_none());
        assert_eq!(old.key_handle.key_id, "replacement");
    }

    #[test]
    fn wrapped_wire_is_pinned_and_has_no_old_reader_escape() {
        let value = wrapped_json();
        assert_eq!(
            value,
            json!({
                "version_number": 2,
                "material": {
                    "kind": "parent_wrapped",
                    "format_version": 1,
                    "provider_ref": "provider-b",
                    "security_domain": "domain:one",
                    "parent_lid": vec![1_u8; 32],
                    "parent_version": 3,
                    "wrapping_context_version": 1,
                    "wrapped_key_format": { "kind": "raw_secret" },
                    "wrapping_mechanism": "unselected-profile",
                    "wrapped_material_ref": "opaque:wrapped-ref"
                },
                "created_at": "2026-09-05T12:00:00Z",
                "is_primary": true
            })
        );
        assert!(value.get("key_handle").is_none());
        assert!(value.get("provider_ref").is_none());
        assert!(serde_json::from_value::<OldVersion>(value.clone()).is_err());
        let mut decoded: KeyVersionRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.material, wrapped().material);
        assert_eq!(decoded.provider_ref().unwrap().as_str(), "provider-b");
        assert!(matches!(
            decoded.resident_handle(),
            Err(crate::error::KeyRackError::Provider(_))
        ));
        assert!(matches!(
            decoded.resident_handle_mut(),
            Err(crate::error::KeyRackError::Provider(_))
        ));
    }

    #[test]
    fn missing_null_unknown_and_conflicting_markers_fail_closed() {
        for marker in [
            Value::Null,
            json!(false),
            json!("parent_wrapped"),
            json!({}),
        ] {
            let mut legacy: Value = serde_json::from_str(LEGACY).unwrap();
            legacy["material"] = marker;
            assert_invalid(legacy);
        }
        let mut value = wrapped_json();
        value.as_object_mut().unwrap().remove("material");
        assert_invalid(value);

        for field in ["key_handle", "provider_ref"] {
            for contents in [
                Value::Null,
                json!("provider-b"),
                json!({"key_id":"escape", "key_spec":"AES256"}),
            ] {
                let mut value = wrapped_json();
                value[field] = contents;
                assert_invalid(value);
            }
        }
        for kind in [
            json!("provider_resident"),
            json!("future_mode"),
            json!(null),
        ] {
            let mut value = wrapped_json();
            value["material"]["kind"] = kind;
            assert_invalid(value);
        }
        for (field, contents) in [
            ("material_mode", json!("parent_wrapped")),
            ("parent_version", json!(3)),
            ("wrapped_material_ref", json!("orphan-hint")),
        ] {
            let mut legacy: Value = serde_json::from_str(LEGACY).unwrap();
            legacy[field] = contents;
            assert_invalid(legacy);
        }
        let mut value = wrapped_json();
        value["material"]["key_handle"] = json!({"key_id":"escape", "key_spec":"AES256"});
        assert_invalid(value);
    }

    #[test]
    fn every_wrapped_field_is_required_and_non_null() {
        let original = wrapped_json();
        let fields: Vec<String> = original["material"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for field in fields {
            let mut missing = original.clone();
            missing["material"].as_object_mut().unwrap().remove(&field);
            assert_invalid(missing);
            let mut null = original.clone();
            null["material"][&field] = Value::Null;
            assert_invalid(null);
        }
    }

    #[test]
    fn unsupported_versions_and_invalid_parent_fail_closed() {
        for field in ["format_version", "wrapping_context_version"] {
            for invalid in [json!(0), json!(2), json!(-1), json!(65536), json!("1")] {
                let mut value = wrapped_json();
                value["material"][field] = invalid;
                assert_invalid(value);
            }
        }
        for invalid in [json!(0), json!(-1), json!("3")] {
            let mut value = wrapped_json();
            value["material"]["parent_version"] = invalid;
            assert_invalid(value);
        }
        let mut value = wrapped_json();
        value["material"]["parent_lid"] = json!("not-a-lid");
        assert_invalid(value);
        let mut zero_version = wrapped();
        zero_version.version_number = 0;
        assert!(serde_json::to_string(&zero_version).is_err());
        let mut value = wrapped_json();
        value["version_number"] = json!(0);
        assert_invalid(value);
    }

    #[test]
    fn wrapping_identifiers_validate_without_normalization() {
        for field in [
            "provider_ref",
            "security_domain",
            "wrapping_mechanism",
            "wrapped_material_ref",
        ] {
            for invalid in [
                String::new(),
                "space name".into(),
                "nul\0name".into(),
                "é".into(),
                "x".repeat(MAX_WRAPPING_IDENTIFIER_BYTES + 1),
            ] {
                let mut value = wrapped_json();
                value["material"][field] = json!(invalid);
                assert_invalid(value);
            }
            let mut value = wrapped_json();
            value["material"][field] = json!("x".repeat(MAX_WRAPPING_IDENTIFIER_BYTES));
            assert!(serde_json::from_value::<KeyVersionRecord>(value).is_ok());
        }
        let original = wrapped();
        let KeyMaterial::ParentWrapped(material) = original.material else {
            unreachable!()
        };
        assert!(ParentWrappedMaterial::new(
            ProviderRef::new(""),
            material.security_domain().clone(),
            material.parent(),
            material.wrapping_context_version(),
            material.key_format().clone(),
            material.mechanism().clone(),
            material.wrapped_material_ref().clone()
        )
        .is_err());
    }

    #[test]
    fn key_format_shapes_are_exact() {
        for valid in [
            json!({"kind":"raw_secret"}),
            json!({"kind":"pkcs8_der"}),
            json!({"kind":"provider_native", "name":"native:v1"}),
        ] {
            let mut value = wrapped_json();
            value["material"]["wrapped_key_format"] = valid;
            let decoded: KeyVersionRecord = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
        for invalid in [
            json!({"kind":"unknown"}),
            json!({"kind":"provider_native"}),
            json!({"kind":"provider_native", "name":""}),
            json!({"kind":"raw_secret", "name":"ignored"}),
            json!({"kind":"pkcs8_der", "name":null}),
            json!({"kind":"raw_secret", "extra":true}),
        ] {
            let mut value = wrapped_json();
            value["material"]["wrapped_key_format"] = invalid;
            assert_invalid(value);
        }
    }

    #[test]
    fn raw_json_duplicate_fields_are_rejected() {
        let value = wrapped_json();
        let text = serde_json::to_string(&value).unwrap();
        let duplicate_material = format!("{{\"material\":{},{}", value["material"], &text[1..]);
        let duplicate_kind = text.replacen(
            "\"parent_wrapped\"",
            "\"parent_wrapped\",\"kind\":\"parent_wrapped\"",
            1,
        );
        let duplicate_format_version = text.replacen(
            "\"format_version\":1",
            "\"format_version\":1,\"format_version\":1",
            1,
        );
        let duplicate_parent = text.replacen(
            "\"parent_version\":3",
            "\"parent_version\":3,\"parent_version\":3",
            1,
        );
        let duplicate_format_kind = text.replacen(
            "\"raw_secret\"",
            "\"raw_secret\",\"kind\":\"raw_secret\"",
            1,
        );
        let duplicate_legacy_binding = LEGACY.replacen(
            "\"provider_ref\":",
            "\"provider_ref\":null,\"provider_ref\":",
            1,
        );
        for invalid in [
            duplicate_material,
            duplicate_kind,
            duplicate_format_version,
            duplicate_parent,
            duplicate_format_kind,
            duplicate_legacy_binding,
        ] {
            let error = serde_json::from_str::<KeyVersionRecord>(&invalid)
                .expect_err("duplicate field accepted");
            assert!(error.to_string().contains("duplicate field"), "{error}");
        }
    }

    #[test]
    fn mixed_record_preserves_actual_material_and_explicit_binding() {
        let mut record = crate::key::tests::make_test_record(KeyState::Enabled);
        record.provider_ref = Some(ProviderRef::new("unrelated-default"));
        record.key_versions.push(wrapped());
        record.current_key_version = 2;
        let json = serde_json::to_string(&record).unwrap();
        let decoded: KeyRecord = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded.get_version(1).unwrap().material,
            KeyMaterial::ProviderResident { .. }
        ));
        assert!(matches!(
            decoded.get_version(2).unwrap().material,
            KeyMaterial::ParentWrapped(_)
        ));
        assert_eq!(
            decoded.effective_provider_ref(2).unwrap().as_str(),
            "provider-b"
        );
        assert_eq!(decoded.lid, record.lid);
        assert!(decoded
            .primary_version()
            .unwrap()
            .resident_handle()
            .is_err());
    }

    proptest! {
        #[test]
        fn explicit_wrapped_bindings_round_trip(
            parent in any::<[u8; 32]>(), version in 1_u64..=u64::MAX,
            provider in "[a-z:]{1,50}", domain in "[a-z:]{1,50}", reference in "[a-z:]{1,50}",
        ) {
            let mut value = wrapped_json();
            value["material"]["parent_lid"] = json!(parent);
            value["material"]["parent_version"] = json!(version);
            value["material"]["provider_ref"] = json!(provider);
            value["material"]["security_domain"] = json!(domain);
            value["material"]["wrapped_material_ref"] = json!(reference);
            let record: KeyVersionRecord = serde_json::from_value(value.clone()).unwrap();
            prop_assert_eq!(serde_json::to_value(&record).unwrap(), value);
            prop_assert!(record.resident_handle().is_err());
        }
    }
}
